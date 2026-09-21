from __future__ import annotations

import gzip
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any

from tests.test_pmacct_rotation_rename_reopen import (
    ROTATION_FUNCTIONS,
    FakeTailer,
    build_namespace,
    initial_lines,
    load_definitions,
    real_compress,
    write_checkpoint,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
PMACCT_SOURCE = (REPO_ROOT / "collector" / "pmacct" / "parse_pmacct.py").read_text(encoding="utf-8")


# Driver executado em um subprocesso REAL. O processo pai envia SIGTERM de
# verdade (sem mock de exceção, sem FakeTailer reutilizado na mesma instância).
# O driver opera SOMENTE sobre o estado persistido em disco (journal, rotated,
# checkpoint) passado pelo pai. Não há hooks no código de produção.
DRIVER = r'''
import json
import os
import sys
import time
import gzip
import shutil
from pathlib import Path

repo_root = Path(sys.argv[1])
config = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
sys.path.insert(0, str(repo_root))

from tests.test_pmacct_rotation_rename_reopen import (
    load_definitions,
    ROTATION_FUNCTIONS,
    build_namespace,
    FakeTailer,
)

PMACCT_SOURCE = (repo_root / "collector" / "pmacct" / "parse_pmacct.py").read_text(encoding="utf-8")

sink = Path(config["sink_path"])
sent = {key: Path(value) for key, value in config["sentinels"].items()}


def real_compress(path):
    gz = path.with_suffix(path.suffix + ".gz")
    part = gz.with_name(gz.name + ".part")
    part.unlink(missing_ok=True)
    with path.open("rb") as src, gzip.open(part, "wb") as dst:
        shutil.copyfileobj(src, dst)
    os.replace(part, gz)
    path.unlink(missing_ok=True)
    return gz


def blocking_compress(path):
    gz = path.with_suffix(path.suffix + ".gz")
    part = gz.with_name(gz.name + ".part")
    part.write_bytes(b"partial")
    sent["gzip_started"].write_text("1")
    while True:
        time.sleep(1)


namespace = build_namespace()
if config.get("behavior") == "block-in-compress":
    namespace["compress_file"] = blocking_compress
else:
    namespace["compress_file"] = real_compress
ns = load_definitions(PMACCT_SOURCE, functions=ROTATION_FUNCTIONS, namespace=namespace)


def ingest(lines):
    with sink.open("a", encoding="utf-8") as handle:
        for line in lines:
            handle.write(line + "\n")
    sent["ingest_called"].write_text(str(len(lines)))
    if config.get("behavior") == "block-in-ingest":
        sent["ingest_blocked"].write_text("1")
        while True:
            time.sleep(1)
    return len(lines)


active = Path(config["active_path"])
state = Path(config["state_path"])
tailer = FakeTailer(state, 0)

sent["ready"].write_text("1")
try:
    recovered = ns["recover_interrupted_rotation"](
        active,
        tailer,
        config.get("compress", True),
        config.get("keep_days", 2),
        ingest,
        reopen_timeout_seconds=config.get("reopen_timeout_seconds", 30.0),
    )
    sent["done"].write_text(json.dumps({"recovered": recovered}))
except BaseException as exc:  # noqa: BLE001
    sent["done"].write_text(json.dumps({"error": str(exc)}))
'''


def _recs(start: int, end: int) -> tuple[str, ...]:
    return tuple(f"record-{i}\n" for i in range(start, end + 1))


class SignalSubprocessTest(unittest.TestCase):
    """M1: SIGTERM real em subprocesso (após rename/pré-reopen, durante drain,
    durante gzip) com reinício a partir do estado em disco. M2: branch dedicado
    de recovery RENAMED+rotated+active-ausente."""

    # ---- helpers ----

    def _ns(self, **overrides: Any) -> dict[str, Any]:
        namespace = build_namespace()
        namespace.update(overrides)
        return load_definitions(PMACCT_SOURCE, functions=ROTATION_FUNCTIONS, namespace=namespace)

    def _make_renamed_state(self, directory: str, records: tuple[str, ...]):
        root = Path(directory)
        active = root / "sensor-1-9995.csv"
        state = root / "state" / "sensor-1-9995.csv.offset.json"
        initial = initial_lines(10)
        active.write_text(initial, encoding="utf-8")
        old_inode = active.stat().st_ino
        drain_offset = len(initial.encode("utf-8"))
        write_checkpoint(state, active, drain_offset)
        rotated = root / "sensor-1-9995.rotated.csv"
        os.replace(active, rotated)
        with rotated.open("a", encoding="utf-8") as handle:
            handle.write("".join(records))
        journal = state.parent / "sensor-1-9995.csv.rotation.json"
        journal.write_text(
            json.dumps(
                {
                    "active_path": str(active),
                    "rotated_path": str(rotated),
                    "old_inode": old_inode,
                    "drain_offset": drain_offset,
                    "state": "RENAMED",
                }
            ),
            encoding="utf-8",
        )
        return active, rotated, journal, state, old_inode, drain_offset

    def _sentinels(self, root: Path, run_id: str) -> dict[str, Path]:
        return {
            "ready": root / f"ready-{run_id}",
            "done": root / f"done-{run_id}",
            "ingest_called": root / f"ingest_called-{run_id}",
            "ingest_blocked": root / f"ingest_blocked-{run_id}",
            "gzip_started": root / f"gzip_started-{run_id}",
        }

    def _spawn(
        self,
        root: Path,
        run_id: str,
        active: Path,
        state: Path,
        sink: Path,
        behavior: str,
        compress: bool = True,
        reopen_timeout_seconds: float = 30.0,
    ) -> tuple[subprocess.Popen, dict[str, Path]]:
        driver = root / "driver.py"
        if not driver.exists():
            driver.write_text(DRIVER, encoding="utf-8")
        sent = self._sentinels(root, run_id)
        config = {
            "workdir": str(root),
            "active_path": str(active),
            "state_path": str(state),
            "sink_path": str(sink),
            "sentinels": {key: str(value) for key, value in sent.items()},
            "behavior": behavior,
            "compress": compress,
            "keep_days": 2,
            "reopen_timeout_seconds": reopen_timeout_seconds,
        }
        cfg_path = root / f"config-{run_id}.json"
        cfg_path.write_text(json.dumps(config), encoding="utf-8")
        proc = subprocess.Popen(
            [sys.executable, str(driver), str(REPO_ROOT), str(cfg_path)],
            cwd=str(root),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return proc, sent

    def _wait(self, path: Path, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return True
            time.sleep(0.05)
        return False

    def _sigterm(self, proc: subprocess.Popen) -> None:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=15)
        self.assertEqual(-signal.SIGTERM, proc.returncode)
        proc.stdout.close()
        proc.stderr.close()

    def _wait_done(self, proc: subprocess.Popen, sent: dict[str, Path]) -> dict[str, Any]:
        if not self._wait(sent["done"], 30):
            proc.wait(timeout=5)
            err = proc.stderr.read().decode(errors="ignore")
            proc.stdout.close()
            proc.stderr.close()
            self.fail(f"driver did not finish; stderr={err}")
        proc.wait(timeout=5)
        proc.stdout.close()
        proc.stderr.close()
        payload = json.loads(sent["done"].read_text(encoding="utf-8"))
        self.assertNotIn("error", payload)
        return payload

    # ---- M1-A: SIGTERM após rename, antes do producer reopen ----

    def test_sigterm_after_rename_before_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = _recs(11, 15)
            active, rotated, journal, state, old_inode, _ = self._make_renamed_state(directory, records)
            sink = root / "sink.txt"

            proc, sent = self._spawn(root, "a1", active, state, sink, behavior="normal")
            self.assertTrue(self._wait(sent["ready"], 15), "driver did not become ready")
            self.assertIsNone(proc.poll())  # still alive, blocked waiting for reopen
            # Enquanto o active está ausente, NÃO pode drenar.
            self.assertFalse(sent["ingest_called"].exists())
            self.assertEqual("RENAMED", json.loads(journal.read_text(encoding="utf-8"))["state"])
            self.assertTrue(rotated.exists())
            self.assertFalse(active.exists())

            self._sigterm(proc)

            # Estado persistido após a morte: journal RENAMED, rotated presente, active ausente.
            self.assertEqual("RENAMED", json.loads(journal.read_text(encoding="utf-8"))["state"])
            self.assertTrue(rotated.exists())
            self.assertFalse(active.exists())
            self.assertEqual("", sink.read_text(encoding="utf-8") if sink.exists() else "")

            # Producer cria active B (novo inode) e uma NOVA instância faz recovery.
            active.write_text("", encoding="utf-8")
            self.assertNotEqual(old_inode, active.stat().st_ino)
            proc2, sent2 = self._spawn(root, "a2", active, state, sink, behavior="normal")
            self.assertTrue(self._wait(sent2["ready"], 15))
            payload = self._wait_done(proc2, sent2)
            self.assertTrue(payload.get("recovered"))

            self.assertEqual(["record-11", "record-12", "record-13", "record-14", "record-15"], sink.read_text(encoding="utf-8").splitlines())
            self.assertFalse(journal.exists())
            self.assertTrue(rotated.with_suffix(rotated.suffix + ".gz").exists())
            self.assertFalse(rotated.exists())

    # ---- M1-B: SIGTERM durante o drain ----

    def test_sigterm_during_drain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = _recs(11, 20)
            active, rotated, journal, state, _old_inode, _ = self._make_renamed_state(directory, records)
            active.write_text("", encoding="utf-8")  # active B já presente (pós-reopen)
            sink = root / "sink.txt"

            proc, sent = self._spawn(root, "b1", active, state, sink, behavior="block-in-ingest")
            self.assertTrue(self._wait(sent["ingest_blocked"], 15), "ingest did not start")
            # Primeiro INSERT persistiu no sink antes do SIGTERM.
            self.assertEqual([f"record-{i}" for i in range(11, 21)], sink.read_text(encoding="utf-8").splitlines())
            self._sigterm(proc)

            # Journal ainda RENAMED (mark INGESTED nunca foi alcançado); rotated preservado.
            self.assertEqual("RENAMED", json.loads(journal.read_text(encoding="utf-8"))["state"])
            self.assertTrue(rotated.exists())

            # Reinício: re-drena do drain_offset (janela at-least-once).
            proc2, sent2 = self._spawn(root, "b2", active, state, sink, behavior="normal")
            self.assertTrue(self._wait(sent2["ready"], 15))
            payload = self._wait_done(proc2, sent2)
            self.assertTrue(payload.get("recovered"))

            drained = sink.read_text(encoding="utf-8").splitlines()
            self.assertEqual([f"record-{i}" for i in range(11, 21)] * 2, drained)
            nums = [int(line.split("-", 1)[1]) for line in drained]
            # Cada passada de drain é uma sequência contígua 11..20 (sem buracos).
            self.assertEqual(list(range(11, 21)), nums[:10])
            self.assertEqual(list(range(11, 21)), nums[10:])
            self.assertEqual(list(range(11, 21)), sorted(set(nums)))  # MISSING=0
            self.assertEqual(10, len(nums) - len(set(nums)))  # DUPLICATES=10 (tail re-drenado)
            self.assertFalse(journal.exists())
            self.assertTrue(rotated.with_suffix(rotated.suffix + ".gz").exists())
            self.assertFalse(rotated.exists())

    # ---- M1-C: SIGTERM durante o gzip ----

    def test_sigterm_during_gzip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = _recs(11, 20)
            active, rotated, journal, state, old_inode, drain_offset = self._make_renamed_state(directory, records)
            active.write_text("", encoding="utf-8")
            expected = rotated.read_text(encoding="utf-8")
            # Promove para INGESTED: drain+ingest já concluídos, gzip prestes a iniciar.
            journal.write_text(
                json.dumps(
                    {
                        "active_path": str(active),
                        "rotated_path": str(rotated),
                        "old_inode": old_inode,
                        "drain_offset": drain_offset,
                        "state": "INGESTED",
                        "drained_size": rotated.stat().st_size,
                    }
                ),
                encoding="utf-8",
            )
            sink = root / "sink.txt"

            proc, sent = self._spawn(root, "c1", active, state, sink, behavior="block-in-compress")
            self.assertTrue(self._wait(sent["gzip_started"], 15), "gzip did not start")
            # .part pode existir; .gz final NÃO pode estar incompleto; CSV preservado.
            self.assertTrue(rotated.with_suffix(rotated.suffix + ".gz.part").exists())
            self.assertFalse(rotated.with_suffix(rotated.suffix + ".gz").exists())
            self.assertTrue(rotated.exists())
            self._sigterm(proc)

            # Após a morte: journal INGESTED, rotated.csv presente, nenhum .gz final.
            self.assertEqual("INGESTED", json.loads(journal.read_text(encoding="utf-8"))["state"])
            self.assertTrue(rotated.exists())
            self.assertFalse(rotated.with_suffix(rotated.suffix + ".gz").exists())

            # Reinício com compressão real: finaliza sem reingestar.
            proc2, sent2 = self._spawn(root, "c2", active, state, sink, behavior="normal")
            self.assertTrue(self._wait(sent2["ready"], 15))
            payload = self._wait_done(proc2, sent2)
            self.assertTrue(payload.get("recovered"))

            gz = rotated.with_suffix(rotated.suffix + ".gz")
            self.assertTrue(gz.exists())
            self.assertFalse(rotated.exists())
            self.assertFalse(journal.exists())
            with gzip.open(gz, "rt", encoding="utf-8") as handle:
                self.assertEqual(expected, handle.read())  # gzip íntegro e completo
            self.assertEqual("", sink.read_text(encoding="utf-8") if sink.exists() else "")  # nenhum re-ingest (DUPLICATES=0)

    # ---- M2: branch dedicado RENAMED + rotated presente + active ausente ----

    def test_pre_reopen_waits_without_draining(self):
        namespace = build_namespace()
        gzip_started: list[bool] = []

        def tracked_compress(path: Path) -> Path:
            gzip_started.append(True)
            return real_compress(path)

        namespace["compress_file"] = tracked_compress
        ns = load_definitions(PMACCT_SOURCE, functions=ROTATION_FUNCTIONS, namespace=namespace)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, rotated, journal, state, old_inode, _ = self._make_renamed_state(directory, _recs(11, 15))
            ingest_calls: list[int] = []
            started = threading.Event()
            result: dict[str, Any] = {}

            def runner() -> None:
                started.set()
                result["recovered"] = ns["recover_interrupted_rotation"](
                    active,
                    FakeTailer(state, 0),
                    True,
                    2,
                    lambda lines: (ingest_calls.append(len(lines)), len(lines))[1],
                    reopen_timeout_seconds=20.0,
                )

            thread = threading.Thread(target=runner)
            thread.start()
            self.assertTrue(started.wait(timeout=5))
            time.sleep(0.2)  # sincronização limitada: deixar a thread entrar no wait loop
            # Enquanto active está ausente, recovery NÃO pode drenar/finalizar.
            self.assertEqual([], ingest_calls)
            self.assertEqual([], gzip_started)
            self.assertEqual("RENAMED", json.loads(journal.read_text(encoding="utf-8"))["state"])
            self.assertTrue(rotated.exists())
            self.assertFalse(active.exists())

            active.write_text("", encoding="utf-8")  # active B com novo inode
            self.assertNotEqual(old_inode, active.stat().st_ino)
            thread.join(timeout=30)
            self.assertFalse(thread.is_alive())
            self.assertTrue(result.get("recovered"))
            self.assertEqual([5], ingest_calls)
            self.assertFalse(journal.exists())
            self.assertTrue(rotated.with_suffix(rotated.suffix + ".gz").exists())

    def test_pre_reopen_timeout_preserves_state(self):
        ns = self._ns()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, rotated, journal, state, _old_inode, _ = self._make_renamed_state(directory, _recs(11, 15))
            ingest_calls: list[int] = []
            recovered = ns["recover_interrupted_rotation"](
                active,
                FakeTailer(state, 0),
                True,
                2,
                lambda lines: (ingest_calls.append(len(lines)), len(lines))[1],
                reopen_timeout_seconds=0.5,
            )
            self.assertFalse(recovered)  # active nunca apareceu
            self.assertEqual([], ingest_calls)
            self.assertEqual("RENAMED", json.loads(journal.read_text(encoding="utf-8"))["state"])
            self.assertTrue(rotated.exists())
            self.assertFalse(active.exists())

    def test_same_inode_active_is_not_treated_as_reopen(self):
        ns = self._ns()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, rotated, journal, state, old_inode, _ = self._make_renamed_state(directory, _recs(11, 15))
            # active passa a apontar para o MESMO inode do rotated (restaurado),
            # não para uma nova geração do producer.
            os.link(rotated, active)
            self.assertEqual(old_inode, active.stat().st_ino)
            ingest_calls: list[int] = []
            recovered = ns["recover_interrupted_rotation"](
                active,
                FakeTailer(state, 0),
                True,
                2,
                lambda lines: (ingest_calls.append(len(lines)), len(lines))[1],
                reopen_timeout_seconds=0.5,
            )
            self.assertFalse(recovered)  # timeout: inode nunca muda
            self.assertEqual([], ingest_calls)
            self.assertEqual("RENAMED", json.loads(journal.read_text(encoding="utf-8"))["state"])
            self.assertTrue(rotated.exists())


if __name__ == "__main__":
    unittest.main()
