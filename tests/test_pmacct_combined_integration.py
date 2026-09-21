from __future__ import annotations

import gzip
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from collector.pmacct import parse_pmacct as pmacct


def _ample_disk(_path) -> types.SimpleNamespace:
    return types.SimpleNamespace(free=100 * 1024**3)


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


class CsvProducer(threading.Thread):
    """Simulates nfacctd: appends valid CSV rows, closes and reopens the
    configured filename every `refresh_seconds` (print_refresh_time)."""

    def __init__(self, path: Path, refresh_seconds: float = 0.03, burst: int = 3, start: int = 0):
        super().__init__(daemon=True)
        self.path = path
        self.refresh_seconds = refresh_seconds
        self.burst = burst
        self.stop_event = threading.Event()
        self.seq = start - 1
        self.errors: list[BaseException] = []

    def run(self) -> None:
        handle = None
        try:
            handle = self.path.open("a", encoding="utf-8")
            while not self.stop_event.is_set():
                for _ in range(self.burst):
                    self.seq += 1
                    handle.write(flow_line(self.seq) + "\n")
                handle.flush()
                handle.close()
                handle = None
                time.sleep(self.refresh_seconds)
                handle = self.path.open("a", encoding="utf-8")
        except BaseException as exc:  # noqa: BLE001
            self.errors.append(exc)
        finally:
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass

    def stop(self) -> None:
        self.stop_event.set()
        self.join(timeout=5)


class RecordingClient:
    def __init__(self) -> None:
        self.rows: list[tuple] = []
        self.insert_calls = 0

    def create_insert_context(self, **kwargs):
        return SimpleContext()

    def insert(self, *args, **kwargs):
        self.insert_calls += 1
        if kwargs.get("context") is not None:
            rows = kwargs["context"].data
        else:
            rows = args[1]
        self.rows.extend(rows)


class SimpleContext:
    data = None


class CombinedIntegrationTest(unittest.TestCase):
    """Parallel parser + durable checkpoint + rename/reopen + journal recovery
    exercised together through the real module (not ast-extracted stubs)."""

    def _config(self, headers: tuple[str, ...]) -> pmacct.ParserConfig:
        return pmacct.ParserConfig(
            output_format="csv",
            delimiter=",",
            fallback_fields=FIELDS,
            headers=headers,
            sensor="sensor-test",
            exporter_ip="203.0.113.1",
            sample_rate=1,
        )

    @mock.patch("shutil.disk_usage", side_effect=_ample_disk)
    def test_parallel_pipeline_drains_and_finalizes_real_rotation(self, _disk_usage):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "sensor-1-9995.csv"
            state_dir = root / "state"
            state_dir.mkdir(parents=True, exist_ok=True)
            state = state_dir / "sensor-1-9995.csv.offset.json"

            header = ",".join(FIELDS)
            n_initial = 120
            with active.open("w", encoding="utf-8") as fh:
                fh.write(header + "\n")
                for i in range(n_initial):
                    fh.write(flow_line(i) + "\n")

            # Real Tailer: consume and commit every line up to EOF, so the
            # durable checkpoint reflects the fully-ingested prefix.
            tailer = pmacct.Tailer(active, state, start_from_end_if_no_state=False)
            while True:
                lines = tailer.read_lines(max_bytes=4 * 1024 * 1024, max_lines=20000)
                if not lines:
                    break
                tailer.commit(force=True)
            committed_offset = tailer.offset
            self.assertEqual(active.stat().st_size, committed_offset)

            # Producer appends more rows and reopens the path (new inode).
            producer = CsvProducer(active, refresh_seconds=0.03, burst=3, start=n_initial)
            producer.start()
            time.sleep(0.06)

            rotated, journal, drain_offset = pmacct.begin_rotation(
                active, tailer, reopen_timeout_seconds=10
            )
            producer.stop()
            self.assertEqual([], producer.errors)

            # The drain offset must match the committed checkpoint (no re-read
            # of already-ingested rows, no gap).
            self.assertEqual(committed_offset, drain_offset)

            # Expected tail = lines appended after the committed checkpoint.
            expected_tail = pmacct.read_complete_lines(rotated, drain_offset)
            self.assertTrue(expected_tail)
            # Full archive content (the .gz preserves the whole rotated file).
            expected_archive_bytes = rotated.read_bytes()

            config = self._config(tuple(FIELDS))
            expected_rows = pmacct.ParallelParser(1).parse(expected_tail, config).rows

            client = RecordingClient()
            writer = pmacct.ClickHouseWriter(client)
            parser = pmacct.ParallelParser(1)

            def ingest(raw_lines: list[str]) -> int:
                parsed = parser.parse(raw_lines, config)
                for error in parsed.errors:
                    print(f"Skipping pmacct line: {error}")
                if parsed.rows:
                    writer.insert(parsed.rows)
                return len(parsed.rows)

            summary = pmacct.drain_and_finalize_rotation(
                rotated, journal, drain_offset, active, tailer, True, 2, ingest
            )

            # Exactly the drained tail was inserted through the parallel
            # pipeline (no missing, no duplicate, no full re-read).
            self.assertEqual(len(expected_rows), len(client.rows))
            self.assertEqual(expected_rows, client.rows)
            self.assertEqual("rename-reopen", summary["method"])

            # Journal cleared, source rotated CSV removed, atomic gzip valid.
            self.assertFalse(journal.exists())
            self.assertFalse(rotated.exists())
            gz = rotated.with_suffix(rotated.suffix + ".gz")
            self.assertTrue(gz.exists())
            with gzip.open(gz, "rb") as fh:
                decompressed = fh.read()
            self.assertEqual(expected_archive_bytes, decompressed)


if __name__ == "__main__":
    unittest.main()

