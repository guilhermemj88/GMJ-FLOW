from __future__ import annotations

import inspect
import json
import os
import sys
import tempfile
import unittest
from concurrent.futures.process import BrokenProcessPool
from pathlib import Path
from unittest import mock


from collector.pmacct import parse_pmacct as pmacct  # noqa: E402


FIELDS = (
    "src_as",
    "dst_as",
    "in_iface",
    "out_iface",
    "src_host",
    "dst_host",
    "src_port",
    "dst_port",
    "tcpflags",
    "proto",
    "timestamp_start",
    "packets",
    "bytes",
)


def flow_line(index: int) -> str:
    return (
        f"64512,64513,1,2,192.0.2.{index % 250 + 1},"
        f"198.51.100.{index % 250 + 1},{1000 + index % 50000},443,"
        f"0x12,tcp,2026-09-15 12:00:{index % 60:02d},10,{1000 + index}"
    )


def parser_config() -> pmacct.ParserConfig:
    return pmacct.ParserConfig(
        output_format="csv",
        delimiter=",",
        fallback_fields=FIELDS,
        headers=None,
        sensor="sensor-test",
        exporter_ip="203.0.113.1",
        sample_rate=1,
    )


def raising_worker(_chunk: pmacct.ParseChunk) -> pmacct.ParsedChunkResult:
    raise RuntimeError("synthetic worker failure")


def dying_worker(_chunk: pmacct.ParseChunk) -> pmacct.ParsedChunkResult:
    os._exit(23)


def inconsistent_worker(chunk: pmacct.ParseChunk) -> pmacct.ParsedChunkResult:
    return pmacct.ParsedChunkResult(chunk.index, [], 1, 0)


def child_module_probe(chunk: pmacct.ParseChunk) -> pmacct.ParsedChunkResult:
    result = pmacct.parse_chunk(chunk)
    result.errors.append(
        f"clickhouse_connect_loaded={'clickhouse_connect' in sys.modules}"
    )
    return result


class RecordingClient:
    def __init__(self, *, fail: bool = False, context: bool = True):
        self.fail = fail
        self.context_enabled = context
        self.context_creations = 0
        self.context_kwargs: list[dict] = []
        self.insert_calls = 0
        self.inserts: list[tuple[tuple, ...]] = []

    def create_insert_context(self, **kwargs):
        self.context_creations += 1
        self.context_kwargs.append(kwargs)
        if not self.context_enabled:
            raise RuntimeError("context unavailable")
        return SimpleInsertContext()

    def insert(self, *args, **kwargs):
        self.insert_calls += 1
        if self.fail:
            raise RuntimeError("insert failed")
        if kwargs.get("context") is not None:
            rows = kwargs["context"].data
        else:
            rows = args[1]
        self.inserts.append(tuple(rows))


class FailingParser:
    def parse(self, _lines, _config):
        raise pmacct.ParallelParseError("parse failed")


class SimpleInsertContext:
    data = None


class FakeExecutor:
    def __init__(self, **_kwargs):
        self.shutdown_args = None

    def shutdown(self, **kwargs):
        self.shutdown_args = kwargs


class BrokenSubmitExecutor:
    def submit(self, *_args, **_kwargs):
        raise BrokenProcessPool("synthetic broken pool")


class ParallelParsingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.lines = [flow_line(index) for index in range(120)]
        cls.expected = pmacct.parse_batch(cls.lines, parser_config(), 1)

    def test_workers_1_matches_sequential_parser(self):
        self.assertEqual(120, self.expected.valid_count)
        self.assertEqual(0, self.expected.invalid_count)
        legacy_rows = []
        headers = None
        for line in self.lines:
            records, headers = pmacct.parse_csv_line(
                line,
                ",",
                list(FIELDS),
                headers,
            )
            legacy_rows.extend(
                pmacct.normalize_flow(
                    record,
                    "sensor-test",
                    "203.0.113.1",
                    1,
                )
                for record in records
            )
        self.assertEqual(legacy_rows, self.expected.rows)

    def test_workers_2_matches_workers_1(self):
        actual = pmacct.parse_batch(self.lines, parser_config(), 2)
        self.assertEqual(self.expected.rows, actual.rows)

    def test_workers_4_matches_workers_1(self):
        actual = pmacct.parse_batch(self.lines, parser_config(), 4)
        self.assertEqual(self.expected.rows, actual.rows)

    def test_workers_1_2_4_preserve_rows_order_counts_and_invalid_skips(self):
        lines = [flow_line(1), "not,enough,fields", flow_line(2), flow_line(3)]
        expected = pmacct.parse_batch(lines, parser_config(), 1)
        for workers in (1, 2, 4):
            with self.subTest(workers=workers):
                actual = pmacct.parse_batch(lines, parser_config(), workers)
                self.assertEqual(expected.rows, actual.rows)
                self.assertEqual(expected.valid_count, actual.valid_count)
                self.assertEqual(expected.invalid_count, actual.invalid_count)
                self.assertEqual(expected.errors, actual.errors)
                self.assertEqual(expected.last_line_ts, actual.last_line_ts)

    def test_out_of_order_completion_is_reassembled(self):
        results = [
            pmacct.ParsedChunkResult(2, [("third",)], 1, 0),
            pmacct.ParsedChunkResult(0, [("first",)], 1, 0),
            pmacct.ParsedChunkResult(1, [("second",)], 1, 0),
        ]
        ordered = pmacct.reassemble_chunk_results(results, [0, 1, 2])
        self.assertEqual(
            [("first",), ("second",), ("third",)],
            [row for result in ordered for row in result.rows],
        )

    def test_worker_exception_fails_closed(self):
        with self.assertRaisesRegex(pmacct.ParallelParseError, "worker failed"):
            pmacct.parse_batch(
                self.lines[:4],
                parser_config(),
                2,
                worker_fn=raising_worker,
            )

    def test_worker_process_death_fails_closed(self):
        with self.assertRaises(pmacct.ParallelParseError):
            pmacct.parse_batch(
                self.lines[:4],
                parser_config(),
                2,
                worker_fn=dying_worker,
            )

    def test_broken_pool_during_submit_is_normalized_and_fails_closed(self):
        with self.assertRaisesRegex(pmacct.ParallelParseError, "worker failed"):
            pmacct.parse_batch(
                self.lines[:4],
                parser_config(),
                2,
                executor=BrokenSubmitExecutor(),
            )

    def test_inconsistent_worker_result_fails_closed(self):
        with self.assertRaisesRegex(
            pmacct.ParallelParseError,
            "inconsistent counters",
        ):
            pmacct.parse_batch(
                self.lines[:4],
                parser_config(),
                1,
                worker_fn=inconsistent_worker,
            )

    def test_invalid_line_remains_skipped(self):
        result = pmacct.parse_batch(["not,enough,fields"], parser_config(), 1)
        self.assertEqual([], result.rows)
        self.assertEqual(1, result.invalid_count)

    def test_csv_header_and_valid_rows_preserve_order(self):
        header = ",".join(FIELDS)
        result = pmacct.parse_batch(
            [header, flow_line(1), flow_line(2)],
            parser_config(),
            2,
        )
        self.assertEqual(2, result.valid_count)
        self.assertEqual(1, result.invalid_count)
        self.assertEqual("192.0.2.2", result.rows[0][3])
        self.assertEqual("192.0.2.3", result.rows[1][3])

    def test_parser_worker_has_no_clickhouse_or_tailer_dependency(self):
        source = inspect.getsource(pmacct.parse_chunk)
        self.assertNotIn("get_client", source)
        self.assertNotIn("ClickHouse", source)
        self.assertNotIn("Tailer", source)
        self.assertNotIn("client.", source)

    def test_child_process_does_not_load_clickhouse_driver(self):
        result = pmacct.parse_batch(
            self.lines[:4],
            parser_config(),
            2,
            worker_fn=child_module_probe,
        )
        self.assertEqual(
            {"clickhouse_connect_loaded=False"},
            set(result.errors),
        )

    def test_real_entrypoint_is_spawn_guarded(self):
        source = Path(pmacct.__file__).read_text(encoding="utf-8")
        self.assertIn('if __name__ == "__main__":\n    main()', source)
        self.assertEqual(1, source.count("\n    main()"))


class TailerBatchTest(unittest.TestCase):
    def make_tailer(self, root: Path, content: bytes) -> pmacct.Tailer:
        data = root / "flows.csv"
        data.write_bytes(content)
        return pmacct.Tailer(data, root / "state.json")

    def test_batch_size_is_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            tailer = self.make_tailer(Path(directory), b"a\nb\nc\n")
            self.assertEqual(["a", "b"], tailer.read_lines(max_lines=2, max_bytes=100))
            self.assertTrue(tailer.last_read_limit_reached)

    def test_max_bytes_is_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            tailer = self.make_tailer(Path(directory), b"aa\nbb\n")
            self.assertEqual(["aa"], tailer.read_lines(max_lines=20, max_bytes=5))
            self.assertEqual(3, tailer.last_read_bytes)
            self.assertTrue(tailer.last_read_limit_reached)

    def test_batch_20k_never_reads_20001(self):
        with tempfile.TemporaryDirectory() as directory:
            content = b"x\n" * 20001
            tailer = self.make_tailer(Path(directory), content)
            lines = tailer.read_lines(max_lines=20000, max_bytes=len(content))
            self.assertEqual(20000, len(lines))

    def test_pending_reads_continue_without_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            tailer = self.make_tailer(Path(directory), b"a\nb\nc\n")
            self.assertEqual(["a"], tailer.read_lines(max_lines=1, max_bytes=100))
            self.assertEqual(["b"], tailer.read_lines(max_lines=1, max_bytes=100))

    def test_no_poll_sleep_during_ready_backlog(self):
        self.assertFalse(pmacct.should_poll_sleep(100))

    def test_poll_sleep_at_eof(self):
        self.assertTrue(pmacct.should_poll_sleep(0))

    def test_poll_sleep_for_incomplete_line(self):
        self.assertTrue(pmacct.should_poll_sleep(100, incomplete_line=True))

    def test_pending_batch_at_eof_sleeps_when_file_has_not_grown(self):
        with tempfile.TemporaryDirectory() as directory:
            tailer = self.make_tailer(Path(directory), b"complete\n")
            self.assertEqual(["complete"], tailer.read_lines())
            self.assertEqual(0, tailer.backlog_bytes())
            self.assertTrue(pmacct.should_poll_sleep(tailer.backlog_bytes()))

    def test_temporary_stat_error_falls_back_to_sleep(self):
        with tempfile.TemporaryDirectory() as directory:
            tailer = self.make_tailer(Path(directory), b"")
            with mock.patch.object(Path, "stat", side_effect=OSError("temporary")):
                self.assertEqual(0, tailer.backlog_bytes())
            self.assertTrue(pmacct.should_poll_sleep(0))

    def test_inode_change_restarts_at_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tailer = self.make_tailer(root, b"old\n")
            tailer.read_lines()
            tailer.commit("old")
            old_inode = tailer.inode
            replacement = root / "replacement.csv"
            replacement.write_bytes(b"new\n")
            os.replace(replacement, tailer.path)
            self.assertNotEqual(old_inode, tailer.path.stat().st_ino)
            self.assertEqual(["new"], tailer.read_lines())
            self.assertEqual(0, tailer.offset)

    def test_truncate_restarts_at_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tailer = self.make_tailer(root, b"one\ntwo\n")
            tailer.read_lines()
            tailer.commit("two")
            tailer.path.write_bytes(b"x\n")
            self.assertEqual(["x"], tailer.read_lines())
            self.assertEqual(0, tailer.offset)


class CheckpointTest(unittest.TestCase):
    def test_atomic_checkpoint_fsyncs_file_and_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "flows.csv"
            data.write_bytes(b"one\n")
            tailer = pmacct.Tailer(data, root / "state.json")
            tailer.read_lines()
            with mock.patch.object(pmacct.os, "fsync", wraps=os.fsync) as fsync:
                tailer.commit("now")
            self.assertGreaterEqual(fsync.call_count, 1 if os.name == "nt" else 2)
            payload = json.loads(tailer.state_path.read_text(encoding="utf-8"))
            self.assertEqual(4, payload["offset"])
            self.assertEqual([], list(root.glob(".*.tmp")))

    def test_failure_before_replace_keeps_previous_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "flows.csv"
            data.write_bytes(b"one\n")
            state = root / "state.json"
            original = {
                "file": str(data),
                "inode": data.stat().st_ino,
                "offset": 0,
                "last_line_ts": "",
            }
            state.write_text(json.dumps(original), encoding="utf-8")
            tailer = pmacct.Tailer(data, state)
            tailer.read_lines()
            with mock.patch.object(pmacct.os, "replace", side_effect=RuntimeError("crash")):
                with self.assertRaisesRegex(RuntimeError, "crash"):
                    tailer.commit("now")
            self.assertEqual(original, json.loads(state.read_text(encoding="utf-8")))
            self.assertEqual(0, tailer.offset)
            self.assertEqual([], list(root.glob(".*.tmp")))

    def test_truncated_invalid_and_empty_checkpoint_fail_closed(self):
        for content in ('{"file":', "not-json", ""):
            with self.subTest(content=content):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    data = root / "flows.csv"
                    data.write_bytes(b"row\n")
                    state = root / "state.json"
                    state.write_text(content, encoding="utf-8")
                    with self.assertRaises(pmacct.CheckpointError) as caught:
                        pmacct.Tailer(
                            data,
                            state,
                            start_from_end_if_no_state=True,
                        )
                    self.assertIs(
                        pmacct.CheckpointStatus.CORRUPT,
                        caught.exception.status,
                    )

    def test_real_missing_checkpoint_can_start_at_eof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "flows.csv"
            data.write_bytes(b"existing\n")
            state = root / "state.json"
            tailer = pmacct.Tailer(data, state, start_from_end_if_no_state=True)
            self.assertEqual(data.stat().st_size, tailer.offset)
            self.assertTrue(state.exists())


class CpuDetectionTest(unittest.TestCase):
    MOUNTINFO_V2 = (
        "29 23 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime "
        "- cgroup2 cgroup rw"
    )
    CGROUP_V2 = "0::/workload"

    @staticmethod
    def reader(values: dict[str, str]):
        return lambda path: values.get(str(path).replace("\\", "/"))

    def effective(self, values: dict[str, str]) -> int:
        return pmacct.effective_cpu_count(
            cpu_count=16,
            affinity_count=16,
            proc_cgroup=self.CGROUP_V2,
            proc_mountinfo=self.MOUNTINFO_V2,
            reader=self.reader(values),
        )

    def test_host_16_without_limits(self):
        self.assertEqual(
            16,
            pmacct.effective_cpu_count(
                cpu_count=16,
                affinity_count=16,
                proc_cgroup="",
                proc_mountinfo="",
            ),
        )
        self.assertEqual(2, pmacct.resolve_parse_workers("auto", 16, auto_max=2))

    def test_cpuset_0_7_yields_8(self):
        self.assertEqual(
            8,
            self.effective(
                {
                    "/sys/fs/cgroup/workload/cpuset.cpus.effective": "0-7",
                    "/sys/fs/cgroup/workload/cpu.max": "max 100000",
                }
            ),
        )

    def test_quota_4_yields_4(self):
        self.assertEqual(
            4,
            self.effective(
                {
                    "/sys/fs/cgroup/workload/cpuset.cpus.effective": "0-15",
                    "/sys/fs/cgroup/workload/cpu.max": "400000 100000",
                }
            ),
        )

    def test_quota_and_cpuset_choose_smallest(self):
        self.assertEqual(
            4,
            self.effective(
                {
                    "/sys/fs/cgroup/workload/cpuset.cpus.effective": "0-7",
                    "/sys/fs/cgroup/workload/cpu.max": "400000 100000",
                }
            ),
        )

    def test_affinity_is_also_respected(self):
        self.assertEqual(
            3,
            pmacct.effective_cpu_count(
                cpu_count=16,
                affinity_count=3,
                proc_cgroup="",
                proc_mountinfo="",
            ),
        )

    def test_auto_is_conservative(self):
        self.assertEqual(1, pmacct.resolve_parse_workers("auto", 4, auto_max=2))
        self.assertEqual(2, pmacct.resolve_parse_workers("auto", 8, auto_max=2))
        self.assertEqual(2, pmacct.resolve_parse_workers("auto", 64, auto_max=2))

    def test_cgroup_v1_quota_and_cpuset(self):
        cgroup = "2:cpu,cpuacct:/docker/a\n3:cpuset:/docker/a"
        mountinfo = (
            "30 23 0:27 /docker/a /sys/fs/cgroup/cpu rw - cgroup cgroup rw,cpu,cpuacct\n"
            "31 23 0:28 / /sys/fs/cgroup/cpuset rw - cgroup cgroup rw,cpuset"
        )
        values = {
            "/sys/fs/cgroup/cpu/cpu.cfs_quota_us": "200000",
            "/sys/fs/cgroup/cpu/cpu.cfs_period_us": "100000",
            "/sys/fs/cgroup/cpuset/docker/a/cpuset.cpus": "0-7",
        }
        self.assertEqual(
            2,
            pmacct.effective_cpu_count(
                cpu_count=16,
                affinity_count=16,
                proc_cgroup=cgroup,
                proc_mountinfo=mountinfo,
                reader=self.reader(values),
            ),
        )

    def test_invalid_worker_configuration_is_rejected(self):
        for value in ("0", "-1", "many"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    pmacct.resolve_parse_workers(value, 16)


class IngestionSafetyTest(unittest.TestCase):
    def prepare(self, root: Path):
        data = root / "flows.csv"
        data.write_text(flow_line(1) + "\n", encoding="utf-8")
        tailer = pmacct.Tailer(data, root / "state.json")
        lines = tailer.read_lines()
        return tailer, lines

    def test_pool_shutdown_is_clean_and_idempotent(self):
        parser = pmacct.ParallelParser(2, executor_factory=FakeExecutor)
        executor = parser.executor
        parser.close()
        parser.close()
        self.assertTrue(parser.closed)
        self.assertEqual(
            {"wait": True, "cancel_futures": True},
            executor.shutdown_args,
        )

    def test_pool_is_reused_across_batches(self):
        with pmacct.ParallelParser(2) as parser:
            executor = parser.executor
            first = parser.parse([flow_line(1), flow_line(2)], parser_config())
            second = parser.parse([flow_line(3), flow_line(4)], parser_config())
            self.assertIs(executor, parser.executor)
        self.assertEqual(2, first.valid_count)
        self.assertEqual(2, second.valid_count)

    def test_shutdown_before_insert_does_not_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            tailer, lines = self.prepare(Path(directory))
            client = RecordingClient()
            with pmacct.ParallelParser(1) as parser:
                with self.assertRaises(pmacct.ShutdownRequested):
                    pmacct.ingest_pending_batch(
                        tailer,
                        pmacct.ClickHouseWriter(client),
                        parser,
                        lines,
                        parser_config(),
                        stop_requested=lambda: True,
                    )
            self.assertEqual(0, tailer.offset)
            self.assertFalse(tailer.state_path.exists())
            self.assertEqual([], client.inserts)

    def test_sigterm_flag_before_insert_does_not_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            tailer, lines = self.prepare(Path(directory))
            controller = pmacct.ShutdownController()
            controller.request(15, None)
            client = RecordingClient()
            with pmacct.ParallelParser(1) as parser:
                with self.assertRaises(pmacct.ShutdownRequested):
                    pmacct.ingest_pending_batch(
                        tailer,
                        pmacct.ClickHouseWriter(client),
                        parser,
                        lines,
                        parser_config(),
                        stop_requested=lambda: controller.requested,
                    )
            self.assertEqual(0, tailer.offset)
            self.assertEqual([], client.inserts)

    def test_insert_failure_does_not_advance_offset(self):
        with tempfile.TemporaryDirectory() as directory:
            tailer, lines = self.prepare(Path(directory))
            client = RecordingClient(fail=True)
            with pmacct.ParallelParser(1) as parser:
                with self.assertRaisesRegex(RuntimeError, "insert failed"):
                    pmacct.ingest_pending_batch(
                        tailer,
                        pmacct.ClickHouseWriter(client),
                        parser,
                        lines,
                        parser_config(),
                    )
            self.assertEqual(0, tailer.offset)
            self.assertFalse(tailer.state_path.exists())

    def test_parse_failure_does_not_insert_or_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            tailer, lines = self.prepare(Path(directory))
            client = RecordingClient()
            with self.assertRaises(pmacct.ParallelParseError):
                pmacct.ingest_pending_batch(
                    tailer,
                    pmacct.ClickHouseWriter(client),
                    FailingParser(),
                    lines,
                    parser_config(),
                )
            self.assertEqual([], client.inserts)
            self.assertEqual(0, tailer.offset)
            self.assertFalse(tailer.state_path.exists())

    def test_worker_process_death_does_not_insert_or_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            tailer, lines = self.prepare(Path(directory))
            client = RecordingClient()
            with pmacct.ParallelParser(2, worker_fn=dying_worker) as parser:
                with self.assertRaises(pmacct.ParallelParseError):
                    pmacct.ingest_pending_batch(
                        tailer,
                        pmacct.ClickHouseWriter(client),
                        parser,
                        lines,
                        parser_config(),
                    )
            self.assertEqual([], client.inserts)
            self.assertEqual(0, tailer.offset)
            self.assertFalse(tailer.state_path.exists())

    def test_insert_context_is_created_once_and_reused(self):
        client = RecordingClient()
        writer = pmacct.ClickHouseWriter(client)
        self.assertTrue(writer.insert([("first",)]))
        self.assertTrue(writer.insert([("second",)]))
        self.assertEqual(1, client.context_creations)
        self.assertEqual(
            [{"table": "flow_raw", "column_names": pmacct.COLUMN_NAMES}],
            client.context_kwargs,
        )
        self.assertEqual([(("first",),), (("second",),)], client.inserts)

    def test_insert_context_has_direct_insert_fallback(self):
        client = RecordingClient(context=False)
        writer = pmacct.ClickHouseWriter(client)
        self.assertFalse(writer.insert([("row",)]))
        self.assertEqual(1, len(client.inserts))
        self.assertIn("context unavailable", writer.context_error)

    def test_context_insert_failure_does_not_retry_direct_insert(self):
        client = RecordingClient(fail=True)
        writer = pmacct.ClickHouseWriter(client)
        with self.assertRaisesRegex(RuntimeError, "insert failed"):
            writer.insert([("row",)])
        self.assertEqual(1, client.insert_calls)
        self.assertEqual([], client.inserts)

    def test_successful_batch_uses_one_insert_then_checkpoints(self):
        with tempfile.TemporaryDirectory() as directory:
            tailer, lines = self.prepare(Path(directory))
            client = RecordingClient()
            with pmacct.ParallelParser(1) as parser:
                pmacct.ingest_pending_batch(
                    tailer,
                    pmacct.ClickHouseWriter(client),
                    parser,
                    lines,
                    parser_config(),
                )
            self.assertEqual(1, len(client.inserts))
            self.assertEqual(tailer.path.stat().st_size, tailer.offset)


class P1ConfigurationContractTest(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[1]

    def test_compose_and_generator_keep_safe_defaults(self):
        collectors = (self.ROOT / "docker-compose.collectors.yml").read_text(
            encoding="utf-8"
        )
        main_compose = (self.ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        backend = (self.ROOT / "backend" / "app" / "main.py").read_text(
            encoding="utf-8"
        )
        for source in (collectors, main_compose, backend):
            self.assertIn("PMACCT_PARSER_BATCH_SIZE-20000", source)
            self.assertIn("PMACCT_PARSER_MAX_BYTES-4194304", source)
            self.assertIn("GMJFLOW_PMACCT_PARSE_WORKERS-1", source)
            self.assertIn("GMJFLOW_PMACCT_PARSE_WORKERS_AUTO_MAX-2", source)
        env_example = (self.ROOT / ".env.example").read_text(encoding="utf-8")
        documentation = (self.ROOT / "docs" / "pmacct.md").read_text(
            encoding="utf-8"
        )
        for source in (env_example, documentation):
            self.assertIn("PMACCT_PARSER_BATCH_SIZE=20000", source)
            self.assertIn("PMACCT_PARSER_MAX_BYTES=4194304", source)
            self.assertIn("GMJFLOW_PMACCT_PARSE_WORKERS=1", source)
            self.assertIn("GMJFLOW_PMACCT_PARSE_WORKERS_AUTO_MAX=2", source)

    def test_status_contract_exposes_p1_metrics(self):
        parser_source = inspect.getsource(pmacct)
        backend = (self.ROOT / "backend" / "app" / "main.py").read_text(
            encoding="utf-8"
        )
        frontend = (self.ROOT / "frontend" / "index.html").read_text(
            encoding="utf-8"
        )
        for key in (
            "parse_workers",
            "effective_cpu_count",
            "batch_rows",
            "parse_ms",
            "insert_ms",
            "cycle_ms",
            "rows_per_second",
        ):
            self.assertIn(f'"{key}"', parser_source)
            self.assertIn(f'"{key}"', backend)
            self.assertIn(f"item.{key}", frontend)


if __name__ == "__main__":
    unittest.main()
