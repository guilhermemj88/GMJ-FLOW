"""Race and edge-behaviour coverage for pmacct rotation (rename-reopen).

Context: the previous "copytruncate-protected" rotation copied the whole active
CSV to a ``.partial`` file and required the source to remain byte-identical
during that copy.  For a multi-GB CSV that nfacctd appends to continuously the
copy window is minutes long, so the guard could never pass (production incident
on 2026-10-09 with a 34.6 GB spool: every retry copied ~34.5 GB and aborted).

The validated replacement renames the active file (O(1)), waits for the
producer to recreate the CSV, drains the renamed file up to EOF and only then
compresses the closed file (atomic ``.gz.part`` -> ``.gz``).

These tests pin the new contract:
- the active file is renamed, never bulk-copied and no ``.partial`` appears;
- the writer reopens a fresh CSV at the active path (new inode);
- the parser resumes from its checkpoint and the renamed file is drained to
  EOF with no loss and no duplication;
- the archive checkpoint records ``file_size == offset`` and ``lag_bytes == 0``;
- compression runs only after the drain, over the closed file;
- unsafe preconditions fail closed (rollback, no rename, no leftover state).

Source of the implementation under test: blob 04aba7c7 (commit b599fa5 /
7fcf681, validated in production on 2026-10-09).
"""

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
    exec(compile(module, "<pmacct-rotation-race-test>", "exec"), values)
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
    """Fake shutil whose copy2 raises: rotation must never copy the active file."""

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
    observed: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Run begin -> drain -> finalize, returning (summary, drained lines)."""
    rotated, journal, drain_offset = ns["begin_rotation"](
        active, tailer, reopen_timeout_seconds=reopen_timeout_seconds
    )
    drained: list[str] = []

    def ingest(lines: list[str]) -> int:
        if observed is not None:
            observed["gz_before_finalize"] = Path(str(rotated) + ".gz").exists()
            observed["rotated_bytes"] = rotated.read_bytes()
        drained.extend(lines)
        return len(lines)

    summary = ns["drain_and_finalize_rotation"](
        rotated, journal, drain_offset, active, tailer, compress, keep_days, ingest
    )
    return summary, drained


class Producer(threading.Thread):
    """Simulates nfacctd: writes bursts, closes and reopens the file every
    ``refresh_seconds`` (print_refresh_time), so a rename is followed by the
    producer recreating the active path with a fresh inode."""

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
            handle = self.path.open("a", encoding="utf-8", newline="")
            while not self.stop_event.is_set():
                for _ in range(self.burst):
                    self.seq += 1
                    handle.write(f"record-{self.seq}\n")
                handle.flush()
                handle.close()
                handle = None
                time.sleep(self.refresh_seconds)
                handle = self.path.open("a", encoding="utf-8", newline="")
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


def record_numbers(lines: list[str]) -> list[int]:
    return [int(line.split("-", 1)[1]) for line in lines if line.strip()]


def initial_lines(n: int) -> str:
    return "".join(f"record-{i}\n" for i in range(1, n + 1))


def write_checkpoint(state: Path, active: Path, offset: int) -> None:
    state.parent.mkdir(parents=True, exist_ok=True)
    state.write_text(json.dumps({"file": str(active), "offset": offset}), encoding="utf-8")


def load_ns(shutil_obj: Any = None) -> dict[str, Any]:
    return load_definitions(
        PMACCT_SOURCE,
        functions=ROTATION_FUNCTIONS,
        namespace=build_namespace(shutil_obj=shutil_obj),
    )


class RotationRaceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.ns = load_ns()

    def test_rotation_never_copies_and_never_creates_partial(self):
        detector = CopyDetector()
        ns = load_ns(shutil_obj=detector)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "sensor-2-9999.csv"
            initial = initial_lines(6)
            active.write_text(initial, encoding="utf-8", newline="")
            state = root / "state" / "sensor-2-9999.csv.offset.json"
            offset = len(initial.encode("utf-8"))
            write_checkpoint(state, active, offset)
            producer = Producer(active, refresh_seconds=0.02, burst=2, start=7)
            producer.start()
            time.sleep(0.05)
            try:
                result, _drained = run_rotation(ns, active, FakeTailer(state, offset))
            finally:
                producer.stop()
            self.assertEqual("rename-reopen", result["method"])
            self.assertEqual(0, detector.copy_calls)
            self.assertEqual([], [p.name for p in root.rglob("*.partial")])

    def test_rename_swaps_inode_and_writer_reopens_fresh_csv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "sensor-2-9999.csv"
            initial = initial_lines(8)
            active.write_text(initial, encoding="utf-8", newline="")
            state = root / "state" / "sensor-2-9999.csv.offset.json"
            offset = len(initial.encode("utf-8"))
            write_checkpoint(state, active, offset)
            tailer = FakeTailer(state, offset)
            old_inode = active.stat().st_ino
            producer = Producer(active, refresh_seconds=0.02, burst=3, start=9)
            producer.start()
            time.sleep(0.05)
            try:
                result, _drained = run_rotation(self.ns, active, tailer)
            finally:
                producer.stop()
            self.assertTrue(active.exists())
            self.assertNotEqual(old_inode, active.stat().st_ino)
            self.assertEqual(1, tailer.reset_calls)
            rotated = Path(result["rotated_to"])
            self.assertTrue(rotated.name.endswith(".csv.gz"))
            self.assertTrue(rotated.exists())
            self.assertTrue(self.ns["rotation_checkpoint_path"](rotated).exists())
            self.assertGreater(active.stat().st_size, 0)

    def test_backlog_is_drained_to_eof_without_loss_or_duplication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "sensor-2-9999.csv"
            initial = initial_lines(5)
            active.write_text(initial, encoding="utf-8", newline="")
            state = root / "state" / "sensor-2-9999.csv.offset.json"
            # parser atrasado: só 4 dos 5 registros já foram ingeridos (backlog)
            backlog_offset = len(initial_lines(4).encode("utf-8"))
            write_checkpoint(state, active, backlog_offset)
            tailer = FakeTailer(state, backlog_offset)
            producer = Producer(active, refresh_seconds=0.01, burst=4, start=6)
            producer.start()
            time.sleep(0.05)
            try:
                _result, drained = run_rotation(self.ns, active, tailer)
            finally:
                producer.stop()
            drained_nums = record_numbers(drained)
            # drena exatamente a partir do checkpoint (registro 5) sem duplicar
            self.assertEqual(list(range(5, drained_nums[-1] + 1)), drained_nums)
            # nenhuma perda: drenado + arquivo novo == sequência completa
            new_nums = record_numbers(active.read_text(encoding="utf-8").splitlines())
            self.assertEqual(list(range(5, producer.seq + 1)), sorted(drained_nums + new_nums))
            self.assertEqual([], producer.errors)

    def test_archive_checkpoint_records_file_size_equal_offset_and_zero_lag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "sensor-2-9999.csv"
            initial = initial_lines(4)
            active.write_text(initial, encoding="utf-8", newline="")
            state = root / "state" / "sensor-2-9999.csv.offset.json"
            offset = len(initial.encode("utf-8"))
            write_checkpoint(state, active, offset)
            producer = Producer(active, refresh_seconds=0.02, burst=3, start=5)
            producer.start()
            time.sleep(0.05)
            observed: dict[str, Any] = {}
            try:
                result, _drained = run_rotation(self.ns, active, FakeTailer(state, offset), observed=observed)
            finally:
                producer.stop()
            rotated = Path(result["rotated_to"])
            checkpoint = json.loads(self.ns["rotation_checkpoint_path"](rotated).read_text(encoding="utf-8"))
            self.assertEqual(str(rotated), checkpoint["archive"])
            self.assertEqual(str(active), checkpoint["source_file"])
            self.assertEqual(checkpoint["file_size"], checkpoint["offset"])
            self.assertEqual(0, checkpoint["lag_bytes"])
            self.assertIs(True, checkpoint["checkpoint_valid"])
            self.assertIs(True, checkpoint["ingestion_complete"])
            # file_size registrado == EOF drenado do arquivo renomeado (fechado)
            self.assertEqual(len(observed["rotated_bytes"]), checkpoint["file_size"])

    def test_compression_runs_only_after_drain_over_the_closed_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "sensor-2-9999.csv"
            initial = initial_lines(3)
            active.write_text(initial, encoding="utf-8", newline="")
            state = root / "state" / "sensor-2-9999.csv.offset.json"
            offset = len(initial.encode("utf-8"))
            write_checkpoint(state, active, offset)
            producer = Producer(active, refresh_seconds=0.02, burst=2, start=4)
            producer.start()
            time.sleep(0.05)
            observed: dict[str, Any] = {}
            try:
                result, drained = run_rotation(self.ns, active, FakeTailer(state, offset), observed=observed)
            finally:
                producer.stop()
            # durante a drenagem não existe .gz algum (compressão ainda não rodou)
            self.assertFalse(observed["gz_before_finalize"])
            gz = Path(result["rotated_to"])
            self.assertTrue(gz.name.endswith(".csv.gz"))
            self.assertTrue(gz.exists())
            # o CSV renomeado foi consumido pela compressão (arquivo fechado)
            self.assertFalse(Path(str(gz)[: -len(".gz")]).exists())
            with gzip.open(gz, "rb") as handle:
                archived = handle.read()
            # o arquivo compactado contém exatamente o conteúdo drenado (nada do CSV novo)
            self.assertEqual(observed["rotated_bytes"], archived)
            archived_nums = record_numbers(archived.decode("utf-8").splitlines())
            self.assertTrue(drained)
            # o gz contém o arquivo inteiro; a drenagem cobre só a cauda desde o checkpoint
            self.assertEqual(archived_nums[-len(drained):], record_numbers(drained))
            self.assertEqual(list(range(1, archived_nums[-1] + 1)), archived_nums)

    def test_missing_producer_rolls_back_and_clears_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "sensor-2-9999.csv"
            initial = initial_lines(3)
            active.write_text(initial, encoding="utf-8", newline="")
            state = root / "state" / "sensor-2-9999.csv.offset.json"
            offset = len(initial.encode("utf-8"))
            write_checkpoint(state, active, offset)
            tailer = FakeTailer(state, offset)
            with self.assertRaises(RuntimeError) as ctx:
                self.ns["begin_rotation"](active, tailer, reopen_timeout_seconds=0.5)
            self.assertIn("producer did not reopen", str(ctx.exception))
            # rollback seguro: arquivo restaurado byte a byte e journal limpo
            self.assertEqual(initial.encode("utf-8"), active.read_bytes())
            self.assertFalse(self.ns["rotation_journal_path"](active, tailer).exists())
            self.assertEqual([], [p.name for p in root.rglob("sensor-2-9999-2*")])

    def test_low_disk_blocks_before_any_rename(self):
        detector = CopyDetector(free_bytes=0)
        ns = load_ns(shutil_obj=detector)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "sensor-2-9999.csv"
            initial = initial_lines(2)
            active.write_text(initial, encoding="utf-8", newline="")
            state = root / "state" / "sensor-2-9999.csv.offset.json"
            write_checkpoint(state, active, len(initial.encode("utf-8")))
            tailer = FakeTailer(state, len(initial.encode("utf-8")))
            with self.assertRaises(RuntimeError) as ctx:
                ns["begin_rotation"](active, tailer, reopen_timeout_seconds=5)
            self.assertIn("insufficient free disk space", str(ctx.exception))
            self.assertEqual(initial.encode("utf-8"), active.read_bytes())
            self.assertFalse(ns["rotation_journal_path"](active, tailer).exists())
            self.assertEqual([], [p.name for p in root.rglob("sensor-2-9999-2*")])

    def test_missing_active_file_blocks_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "sensor-2-9999.csv"
            state = root / "state" / "sensor-2-9999.csv.offset.json"
            write_checkpoint(state, active, 0)
            with self.assertRaises(RuntimeError) as ctx:
                self.ns["begin_rotation"](active, FakeTailer(state, 0), reopen_timeout_seconds=1)
            self.assertIn("active pmacct CSV does not exist", str(ctx.exception))

    def test_missing_checkpoint_blocks_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "sensor-2-9999.csv"
            initial = initial_lines(2)
            active.write_text(initial, encoding="utf-8", newline="")
            state = root / "state" / "sensor-2-9999.csv.offset.json"
            with self.assertRaises(RuntimeError) as ctx:
                self.ns["begin_rotation"](active, FakeTailer(state, 0), reopen_timeout_seconds=1)
            self.assertIn("requires a valid parser checkpoint", str(ctx.exception))
            self.assertEqual(initial.encode("utf-8"), active.read_bytes())

    def test_reopen_wait_ignores_same_inode_rewrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active = root / "sensor-2-9999.csv"
            active.write_text("record-1\n", encoding="utf-8", newline="")
            inode = active.stat().st_ino
            # o produtor reescreve o MESMO inode: não conta como reopen
            active.write_text("record-2\n", encoding="utf-8", newline="")
            with self.assertRaises(RuntimeError) as ctx:
                self.ns["_wait_for_producer_reopen"](active, inode, 0.4)
            self.assertIn("producer did not reopen", str(ctx.exception))


class RotationSourceContractTest(unittest.TestCase):
    def test_rename_reopen_markers_present_and_copytruncate_removed(self):
        # guarda de regressão: o comportamento validado em produção deve permanecer
        self.assertIn('"method": "rename-reopen"', PMACCT_SOURCE)
        self.assertIn("os.replace(output_file, rotated)", PMACCT_SOURCE)
        self.assertIn("_wait_for_producer_reopen", PMACCT_SOURCE)
        self.assertIn("producer did not reopen the output file", PMACCT_SOURCE)
        # nenhum resquício do rotator antigo (cópia integral + .partial)
        self.assertNotIn("copytruncate", PMACCT_SOURCE)
        self.assertNotIn("active CSV changed while it was copied", PMACCT_SOURCE)
        self.assertNotIn("shutil.copy2(output_file", PMACCT_SOURCE)
        self.assertNotIn(".partial", PMACCT_SOURCE)


if __name__ == "__main__":
    unittest.main()
