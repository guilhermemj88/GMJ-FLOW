from __future__ import annotations

import gzip
import json
import shutil as _shutil
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

from tests.test_pmacct_rotation_rename_reopen import (
    ROTATION_FUNCTIONS,
    FakeTailer,
    Producer,
    build_namespace,
    initial_lines,
    load_definitions,
    write_checkpoint,
)


PMACCT_PATH = Path(__file__).resolve().parents[1] / "collector" / "pmacct" / "parse_pmacct.py"
PMACCT_SOURCE = PMACCT_PATH.read_text(encoding="utf-8")


class CrashRecoveryTest(unittest.TestCase):
    """Crash-safety tests: a SIGTERM/kill at any point in the rotation must
    never silently lose the drained tail. Recovery is journal-driven."""

    def _ns(self, **namespace_overrides: Any) -> dict[str, Any]:
        namespace = build_namespace()
        namespace.update(namespace_overrides)
        return load_definitions(PMACCT_SOURCE, functions=ROTATION_FUNCTIONS, namespace=namespace)

    def _setup(self, directory: str) -> tuple[Path, Path, int]:
        root = Path(directory)
        active = root / "sensor-1-9995.csv"
        active.write_text(initial_lines(10), encoding="utf-8")
        state = root / "state" / "sensor-1-9995.csv.offset.json"
        offset = len(initial_lines(10).encode("utf-8"))
        write_checkpoint(state, active, offset)
        return active, state, offset

    def test_crash_after_rename_recovers_tail(self):
        ns = self._ns()
        with tempfile.TemporaryDirectory() as directory:
            active, state, offset = self._setup(directory)
            producer = Producer(active, refresh_seconds=0.02, burst=5, start=11)
            producer.start()
            time.sleep(0.05)
            # Crash point: rename happened, drain/ingest never ran.
            rotated, journal, _drain_offset = ns["begin_rotation"](
                active, FakeTailer(state, offset), reopen_timeout_seconds=10
            )
            producer.stop()

            drained: list[str] = []
            recovered = ns["recover_interrupted_rotation"](
                active, FakeTailer(state, offset), True, 2,
                lambda lines: (drained.extend(lines), len(lines))[1],
            )
            self.assertTrue(recovered)
            self.assertTrue(drained)
            nums = [int(line.split("-", 1)[1]) for line in drained if line.startswith("record-")]
            self.assertEqual(11, nums[0])
            self.assertEqual(nums, sorted(nums))
            self.assertEqual(list(range(11, nums[-1] + 1)), nums)
            # Finalized: journal cleared, archive present, source cleaned up.
            self.assertFalse(journal.exists())
            self.assertTrue(rotated.with_suffix(rotated.suffix + ".gz").exists())
            self.assertFalse(rotated.exists())

    def test_crash_mid_drain_reingests_without_loss(self):
        ns = self._ns()
        with tempfile.TemporaryDirectory() as directory:
            active, state, offset = self._setup(directory)
            producer = Producer(active, refresh_seconds=0.02, burst=5, start=11)
            producer.start()
            time.sleep(0.05)
            rotated, journal, drain_offset = ns["begin_rotation"](
                active, FakeTailer(state, offset), reopen_timeout_seconds=10
            )
            producer.stop()

            # First drain + INSERT happened, but the process died before the
            # journal was marked INGESTED.
            first = list(ns["read_complete_lines"](rotated, drain_offset))
            self.assertTrue(first)

            second: list[str] = []
            recovered = ns["recover_interrupted_rotation"](
                active, FakeTailer(state, offset), False, 2,
                lambda lines: (second.extend(lines), len(lines))[1],
            )
            self.assertTrue(recovered)
            # At-least-once: the tail is re-drained in full (duplicates allowed).
            self.assertEqual(first, second)
            self.assertFalse(journal.exists())

    def test_crash_after_gzip_before_source_unlink(self):
        ns = self._ns()
        with tempfile.TemporaryDirectory() as directory:
            active, state, offset = self._setup(directory)
            producer = Producer(active, refresh_seconds=0.02, burst=5, start=11)
            producer.start()
            time.sleep(0.05)
            rotated, journal, drain_offset = ns["begin_rotation"](
                active, FakeTailer(state, offset), reopen_timeout_seconds=10
            )
            producer.stop()

            drained: list[str] = []
            ns["drain_and_finalize_rotation"](
                rotated, journal, drain_offset, active, FakeTailer(state, offset), False, 2,
                lambda lines: (drained.extend(lines), len(lines))[1],
            )
            # Rebuild the INGESTED + gzip-written-but-source-not-unlinked state.
            gz_path = rotated.with_suffix(rotated.suffix + ".gz")
            rotated.write_text(rotated.read_text(encoding="utf-8"), encoding="utf-8")
            with rotated.open("rb") as src, gzip.open(gz_path, "wb") as dst:
                _shutil.copyfileobj(src, dst)
            payload = {
                "active_path": str(active),
                "rotated_path": str(rotated),
                "old_inode": 0,
                "drain_offset": drain_offset,
                "state": "INGESTED",
                "drained_size": rotated.stat().st_size,
            }
            journal.write_text(json.dumps(payload), encoding="utf-8")

            recovered = ns["recover_interrupted_rotation"](
                active, FakeTailer(state, offset), True, 2,
                lambda lines: 0,
            )
            self.assertTrue(recovered)
            self.assertFalse(rotated.exists())
            self.assertTrue(gz_path.exists())
            self.assertFalse(journal.exists())

    def test_compress_failure_keeps_journal_and_retries(self):
        calls: dict[str, int] = {"n": 0}

        def flaky_compress(path: Path) -> Path:
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("gzip boom")
            gz = path.with_suffix(path.suffix + ".gz")
            with path.open("rb") as src, gzip.open(gz, "wb") as dst:
                _shutil.copyfileobj(src, dst)
            path.unlink(missing_ok=True)
            return gz

        ns = self._ns(compress_file=flaky_compress)
        with tempfile.TemporaryDirectory() as directory:
            active, state, offset = self._setup(directory)
            producer = Producer(active, refresh_seconds=0.02, burst=5, start=11)
            producer.start()
            time.sleep(0.05)
            rotated, journal, drain_offset = ns["begin_rotation"](
                active, FakeTailer(state, offset), reopen_timeout_seconds=10
            )
            producer.stop()

            with self.assertRaises(OSError):
                ns["drain_and_finalize_rotation"](
                    rotated, journal, drain_offset, active, FakeTailer(state, offset), True, 2,
                    lambda lines: len(lines),
                )
            # The journal was already marked INGESTED before the compress step;
            # the rotated CSV must survive for the next recovery to finish it.
            payload = json.loads(journal.read_text(encoding="utf-8"))
            self.assertEqual("INGESTED", payload["state"])
            self.assertTrue(rotated.exists())
            self.assertFalse(rotated.with_suffix(rotated.suffix + ".gz").exists())

            recovered = ns["recover_interrupted_rotation"](
                active, FakeTailer(state, offset), True, 2,
                lambda lines: 0,
            )
            self.assertTrue(recovered)
            self.assertFalse(rotated.exists())
            self.assertTrue(rotated.with_suffix(rotated.suffix + ".gz").exists())
            self.assertFalse(journal.exists())
            self.assertEqual(2, calls["n"])

    def test_stale_renamed_journal_without_rotated_is_cleared(self):
        ns = self._ns()
        with tempfile.TemporaryDirectory() as directory:
            active, state, offset = self._setup(directory)
            journal = ns["rotation_journal_path"](active, FakeTailer(state, offset))
            journal.write_text(
                json.dumps({"rotated_path": str(Path(directory) / "gone.csv"), "state": "RENAMED"}),
                encoding="utf-8",
            )
            recovered = ns["recover_interrupted_rotation"](
                active, FakeTailer(state, offset), False, 2, lambda lines: 0
            )
            self.assertFalse(recovered)
            self.assertFalse(journal.exists())

    def test_no_journal_is_noop(self):
        ns = self._ns()
        with tempfile.TemporaryDirectory() as directory:
            active, state, offset = self._setup(directory)
            recovered = ns["recover_interrupted_rotation"](
                active, FakeTailer(state, offset), False, 2, lambda lines: 0
            )
            self.assertFalse(recovered)

    def test_end_to_end_continuity_across_crash(self):
        ns = self._ns()
        with tempfile.TemporaryDirectory() as directory:
            active, state, offset = self._setup(directory)
            producer = Producer(active, refresh_seconds=0.01, burst=5, start=11)
            producer.start()
            time.sleep(0.05)
            rotated, journal, drain_offset = ns["begin_rotation"](
                active, FakeTailer(state, offset), reopen_timeout_seconds=10
            )
            time.sleep(0.05)
            producer.stop()

            drained: list[str] = []
            recovered = ns["recover_interrupted_rotation"](
                active, FakeTailer(state, offset), False, 2,
                lambda lines: (drained.extend(lines), len(lines))[1],
            )
            self.assertTrue(recovered)

            drained_nums = [int(line.split("-", 1)[1]) for line in drained if line.startswith("record-")]
            self.assertTrue(drained_nums)
            self.assertEqual(11, drained_nums[0])
            self.assertEqual(drained_nums, sorted(drained_nums))
            self.assertEqual(list(range(11, drained_nums[-1] + 1)), drained_nums)

            active_nums = [
                int(line.split("-", 1)[1])
                for line in ns["read_complete_lines"](active, 0)
                if line.startswith("record-")
            ]
            if active_nums:
                self.assertEqual(active_nums, sorted(active_nums))
                self.assertEqual(drained_nums[-1] + 1, active_nums[0])

            self.assertFalse(journal.exists())


class AtomicGzipTest(unittest.TestCase):
    def test_compress_file_is_atomic(self):
        ns = load_definitions(
            PMACCT_SOURCE, functions=("compress_file",), namespace={"shutil": _shutil}
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "s.csv"
            path.write_text("line1\nline2\n", encoding="utf-8")
            gz = ns["compress_file"](path)
            self.assertTrue(gz.exists())
            self.assertFalse(path.exists())
            self.assertFalse(Path(str(gz) + ".part").exists())
            with gzip.open(gz, "rt", encoding="utf-8") as handle:
                self.assertEqual("line1\nline2\n", handle.read())

    def test_compress_failure_leaves_no_partial_gz(self):
        class BoomShutil:
            def copyfileobj(self, src: Any, dst: Any) -> None:
                dst.write(b"partial")
                raise OSError("boom")

        ns = load_definitions(
            PMACCT_SOURCE, functions=("compress_file",), namespace={"shutil": BoomShutil()}
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "s.csv"
            path.write_text("x" * 100, encoding="utf-8")
            with self.assertRaises(OSError):
                ns["compress_file"](path)
            self.assertFalse(path.with_suffix(path.suffix + ".gz").exists())
            self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()
