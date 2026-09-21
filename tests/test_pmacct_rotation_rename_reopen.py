from __future__ import annotations

import ast
import gzip
import json
import os
import shutil as _shutil
import tempfile
import threading
import time
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PMACCT_PATH = ROOT / "collector" / "pmacct" / "parse_pmacct.py"
PMACCT_SOURCE = PMACCT_PATH.read_text(encoding="utf-8")


def load_definitions(source: str, *, functions: tuple[str, ...], namespace: dict[str, Any] | None = None) -> dict[str, Any]:
    tree = ast.parse(source)
    selected = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in functions:
            node.decorator_list = []
            selected.append(node)
    module = ast.Module(
        body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), *selected],
        type_ignores=[],
    )
    ast.fix_missing_locations(module)
    values: dict[str, Any] = {
        "Path": Path,
        "datetime": datetime,
        "timezone": timezone,
        "json": json,
        "time": time,
        "os": os,
        "gzip": gzip,
    }
    values.update(namespace or {})
    exec(compile(module, "<pmacct-rotation-test>", "exec"), values)
    return values


ROTATION_FUNCTIONS = (
    "begin_rotation",
    "drain_and_finalize_rotation",
    "finish_rotation",
    "mark_rotation_ingested",
    "recover_interrupted_rotation",
    "_wait_for_producer_reopen",
    "read_complete_lines",
    "rotation_checkpoint_path",
    "read_json",
    "atomic_write_json",
    "rotation_journal_path",
)


class FakeTailer:
    def __init__(self, state_path: Path, offset: int):
        self.state_path = state_path
        self.offset = offset
        self.reset_calls = 0

    def reset_for_new_file(self) -> None:
        self.reset_calls += 1


class CopyDetector:
    """Fake shutil whose copy2 raises: the rotation must never copy."""

    def __init__(self, free_bytes: int = 100 * 1024**3):
        self.free_bytes = free_bytes
        self.copy_calls = 0

    def disk_usage(self, _path: Path) -> types.SimpleNamespace:
        return types.SimpleNamespace(free=self.free_bytes)

    def copy2(self, src: Path, dst: Path) -> None:
        self.copy_calls += 1
        raise AssertionError("rotation must not copy the active file")


def real_compress(path: Path) -> Path:
    gz = path.with_suffix(path.suffix + ".gz")
    with path.open("rb") as src, gzip.open(gz, "wb") as dst:
        _shutil.copyfileobj(src, dst)
    path.unlink(missing_ok=True)
    return gz


def real_write_status(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def no_cleanup(_directory: Path, _keep_days: int, active_file: Path | None = None) -> int:
    return 0


def build_namespace(shutil_obj: Any = None) -> dict[str, Any]:
    return {
        "shutil": shutil_obj if shutil_obj is not None else CopyDetector(),
        "safe_int": lambda value, default=0, minimum=0, maximum=None: int(value),
        "compress_file": real_compress,
        "write_status": real_write_status,
        "cleanup_old_rotations": no_cleanup,
    }


def run_rotation(
    ns: dict[str, Any],
    active: Path,
    tailer: FakeTailer,
    compress: bool = True,
    keep_days: int = 2,
    reopen_timeout_seconds: float = 10.0,
) -> tuple[dict[str, Any], list[str]]:
    """Run a full begin -> drain -> finalize rotation against the extracted
    functions, returning (summary, drained_lines)."""
    rotated, journal, drain_offset = ns["begin_rotation"](
        active, tailer, reopen_timeout_seconds=reopen_timeout_seconds
    )
    drained: list[str] = []

    def ingest(lines: list[str]) -> int:
        drained.extend(lines)
        return len(lines)

    summary = ns["drain_and_finalize_rotation"](
        rotated, journal, drain_offset, active, tailer, compress, keep_days, ingest
    )
    return summary, drained


class Producer(threading.Thread):
    """Simulates nfacctd: holds an append FD, writes bursts, then closes and
    reopens the file every `refresh_seconds` (print_refresh_time)."""

    def __init__(self, path: Path, refresh_seconds: float = 0.02, burst: int = 5, start: int = 1):
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
                    handle.write(f"record-{self.seq}\n")
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


def initial_lines(n: int) -> str:
    return "".join(f"record-{i}\n" for i in range(1, n + 1))


def write_checkpoint(state: Path, active: Path, offset: int) -> None:
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps({"file": str(active), "offset": offset}), encoding="utf-8")


class RotationRenameReopenTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ns = load_definitions(
            PMACCT_SOURCE,
            functions=ROTATION_FUNCTIONS,
            namespace=build_namespace(),
        )

    def test_rotation_succeeds_without_copying(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "sensor-1-9995.csv"
            initial = initial_lines(10)
            active.write_text(initial, encoding="utf-8")
            state = root / "state" / "sensor-1-9995.csv.offset.json"
            old_inode = active.stat().st_ino
            offset = len(initial.encode("utf-8"))
            write_checkpoint(state, active, offset)
            tailer = FakeTailer(state, offset)
            producer = Producer(active, refresh_seconds=0.02, burst=5)
            producer.start()
            time.sleep(0.05)
            result, drained = run_rotation(self.ns, active, tailer, compress=True, keep_days=2)
            producer.stop()
            self.assertEqual("rename-reopen", result["method"])
            self.assertTrue(active.exists())
            self.assertNotEqual(old_inode, active.stat().st_ino)
            rotated = Path(result["rotated_to"])
            self.assertTrue(rotated.exists())
            self.assertTrue(rotated.name.endswith(".gz"))
            self.assertTrue(self.ns["rotation_checkpoint_path"](rotated).exists())
            self.assertEqual(1, tailer.reset_calls)
            self.assertGreaterEqual(len(drained), 1)

    def test_no_copy_is_made(self):
        detector = CopyDetector()
        ns = load_definitions(
            PMACCT_SOURCE,
            functions=ROTATION_FUNCTIONS,
            namespace=build_namespace(shutil_obj=detector),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "sensor-1-9995.csv"
            initial = initial_lines(5)
            active.write_text(initial, encoding="utf-8")
            state = root / "state" / "sensor-1-9995.csv.offset.json"
            offset = len(initial.encode("utf-8"))
            write_checkpoint(state, active, offset)
            producer = Producer(active, refresh_seconds=0.02, burst=3)
            producer.start()
            time.sleep(0.04)
            run_rotation(ns, active, FakeTailer(state, offset), compress=False, keep_days=2)
            producer.stop()
            self.assertEqual(0, detector.copy_calls)


class ContinuityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ns = load_definitions(
            PMACCT_SOURCE,
            functions=ROTATION_FUNCTIONS,
            namespace=build_namespace(),
        )

    def test_no_missing_no_duplicate_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "sensor-1-9995.csv"
            initial = initial_lines(20)
            active.write_text(initial, encoding="utf-8")
            state = root / "state" / "sensor-1-9995.csv.offset.json"
            offset = len(initial.encode("utf-8"))
            write_checkpoint(state, active, offset)
            producer = Producer(active, refresh_seconds=0.01, burst=7, start=21)
            producer.start()
            time.sleep(0.05)
            _result, drained = run_rotation(self.ns, active, FakeTailer(state, offset), compress=False, keep_days=2)
            producer.stop()

            self.assertTrue(drained)
            nums = []
            for line in drained:
                self.assertTrue(line.startswith("record-"), line)
                nums.append(int(line.split("-", 1)[1]))
            self.assertEqual(nums, sorted(nums))
            self.assertEqual(21, nums[0])
            self.assertEqual(list(range(21, nums[-1] + 1)), nums)


class StressTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ns = load_definitions(
            PMACCT_SOURCE,
            functions=ROTATION_FUNCTIONS,
            namespace=build_namespace(),
        )

    def test_many_rapid_rotations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "sensor-1-9995.csv"
            active.write_text("", encoding="utf-8")
            producer = Producer(active, refresh_seconds=0.005, burst=3)
            producer.start()
            failures = 0
            total_drained = 0
            for i in range(60):
                if not active.exists():
                    active.write_text("", encoding="utf-8")
                state = root / "state" / "sensor-1-9995.csv.offset.json"
                offset = active.stat().st_size
                write_checkpoint(state, active, offset)
                try:
                    _summary, drained = run_rotation(
                        self.ns, active, FakeTailer(state, offset), compress=(i % 2 == 0), keep_days=2
                    )
                    total_drained += len(drained)
                except Exception:
                    failures += 1
            producer.stop()
            self.assertEqual(0, failures)
            self.assertGreater(total_drained, 0)


class FailureInjectionTest(unittest.TestCase):
    def _ns(self, shutil_obj: Any = None) -> dict[str, Any]:
        return load_definitions(
            PMACCT_SOURCE,
            functions=ROTATION_FUNCTIONS,
            namespace=build_namespace(shutil_obj=shutil_obj),
        )

    def test_no_producer_restores_file(self):
        ns = self._ns()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "sensor-1-9995.csv"
            active.write_text("record-1\n", encoding="utf-8")
            state = root / "state" / "sensor-1-9995.csv.offset.json"
            write_checkpoint(state, active, 9)
            tailer = FakeTailer(state, 9)
            with self.assertRaises(RuntimeError) as ctx:
                ns["begin_rotation"](active, tailer, reopen_timeout_seconds=0.5)
            self.assertIn("producer did not reopen", str(ctx.exception))
            self.assertTrue(active.exists())
            self.assertEqual("record-1\n", active.read_text(encoding="utf-8"))
            # The journal intent must be cleared after the restore.
            journal = ns["rotation_journal_path"](active, tailer)
            self.assertFalse(journal.exists())

    def test_low_disk_blocks_before_rename(self):
        detector = CopyDetector(free_bytes=0)
        ns = self._ns(shutil_obj=detector)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "sensor-1-9995.csv"
            active.write_text("record-1\n", encoding="utf-8")
            state = root / "state" / "sensor-1-9995.csv.offset.json"
            write_checkpoint(state, active, 9)
            with self.assertRaises(RuntimeError) as ctx:
                ns["begin_rotation"](active, FakeTailer(state, 9), reopen_timeout_seconds=10)
            self.assertIn("insufficient free disk space", str(ctx.exception))
            self.assertTrue(active.exists())
            self.assertEqual("record-1\n", active.read_text(encoding="utf-8"))


class MultiSensorIsolationTest(unittest.TestCase):
    def test_sensor1_rotation_does_not_touch_sensor3(self):
        ns = load_definitions(
            PMACCT_SOURCE,
            functions=ROTATION_FUNCTIONS,
            namespace=build_namespace(),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            s1 = root / "sensor-1-9995.csv"
            s3 = root / "sensor-3-9997.csv"
            s1.write_text("r1\n", encoding="utf-8")
            s3.write_text("r3\n", encoding="utf-8")
            st1 = root / "state" / "sensor-1-9995.csv.offset.json"
            st3 = root / "state" / "sensor-3-9997.csv.offset.json"
            write_checkpoint(st1, s1, 3)
            write_checkpoint(st3, s3, 3)
            p1 = Producer(s1, refresh_seconds=0.02, burst=3)
            p3 = Producer(s3, refresh_seconds=0.02, burst=3)
            p1.start()
            p3.start()
            time.sleep(0.04)
            run_rotation(ns, s1, FakeTailer(st1, 3), compress=False, keep_days=2)
            time.sleep(0.05)
            p3.stop()
            p1.stop()
            self.assertTrue(s3.exists())
            self.assertGreater(s3.stat().st_size, 3)
            self.assertEqual(0, len(p3.errors))


if __name__ == "__main__":
    unittest.main()
