from __future__ import annotations

import ast
import json
import os
import tempfile
import time
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PMACCT_PATH = ROOT / "collector" / "pmacct" / "parse_pmacct.py"
PMACCT_SOURCE = PMACCT_PATH.read_text(encoding="utf-8")


def load_definitions(
    source: str,
    *,
    functions: tuple[str, ...] = (),
    namespace: dict[str, Any] | None = None,
) -> dict[str, Any]:
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
    }
    values.update(namespace or {})
    exec(compile(module, "<pmacct-rotation-race-test>", "exec"), values)
    return values


class FakeTailer:
    def __init__(self, state_path: Path, offset: int):
        self.state_path = state_path
        self.offset = offset

    def reset_for_new_file(self) -> None:
        pass


def _make_fake_shutil(grow: bool, free_bytes: int = 100 * 1024**3):
    """copy2 que, quando grow=True, simula o nfacctd gravando no CSV ativo
    durante a cópia (aumenta o tamanho do arquivo de origem após copiar)."""

    def copy2(src: Path, dst: Path) -> None:
        dst.write_bytes(src.read_bytes())
        if grow:
            with src.open("ab") as handle:
                handle.write(b"EXTRA")

    def disk_usage(_path: Path) -> types.SimpleNamespace:
        return types.SimpleNamespace(free=free_bytes)

    return types.SimpleNamespace(copy2=copy2, disk_usage=disk_usage)


def _compress_file(path: Path) -> Path:
    gz = path.with_suffix(path.suffix + ".gz")
    gz.write_bytes(path.read_bytes())
    path.unlink()
    return gz


def _write_status(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _cleanup_old_rotations(directory: Path, keep_days: int, active_file: Path | None = None) -> int:
    return 0


def _build_namespace(grow: bool = False, free_bytes: int = 100 * 1024**3) -> dict[str, Any]:
    return {
        "shutil": _make_fake_shutil(grow, free_bytes=free_bytes),
        "safe_int": lambda value, default=0, minimum=0, maximum=None: int(value),
        "compress_file": _compress_file,
        "write_status": _write_status,
        "cleanup_old_rotations": _cleanup_old_rotations,
    }


class RotationRaceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ns_stable = load_definitions(
            PMACCT_SOURCE,
            functions=("rotate_output_file", "rotation_checkpoint_path"),
            namespace=_build_namespace(grow=False),
        )
        cls.ns_grow = load_definitions(
            PMACCT_SOURCE,
            functions=("rotate_output_file", "rotation_checkpoint_path"),
            namespace=_build_namespace(grow=True),
        )
        cls.ns_low_disk = load_definitions(
            PMACCT_SOURCE,
            functions=("rotate_output_file", "rotation_checkpoint_path"),
            namespace=_build_namespace(grow=False, free_bytes=0),
        )

    def _setup(self, root: Path, ns: dict[str, Any]):
        active = root / "sensor-1-9995.csv"
        active.write_bytes(b"abcdef")  # 6 bytes
        state = root / "state" / "sensor-1-9995.csv.offset.json"
        state.parent.mkdir(parents=True, exist_ok=True)
        state.write_text(json.dumps({"file": str(active), "offset": 6}), encoding="utf-8")
        tailer = FakeTailer(state, 6)
        return active, tailer, ns

    # A. copy estável -> rotação normal (atômica, método protegido)
    def test_stable_copy_rotates_normally(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, tailer, ns = self._setup(root, self.ns_stable)
            result = ns["rotate_output_file"](active, tailer, compress=True, keep_days=2)
            self.assertEqual("copytruncate-protected", result["method"])
            self.assertTrue(result["compressed"])
            # CSV ativo truncado (rotação normal)
            self.assertEqual(0, active.stat().st_size)
            # arquivo rotacionado (.gz) + checkpoint existem
            rotated = Path(result["rotated_to"])
            self.assertTrue(rotated.exists())
            self.assertTrue(ns["rotation_checkpoint_path"](rotated).exists())

    # B. arquivo ativo cresce durante copy -> cópia parcial removida + aborta
    def test_growing_active_removes_partial_copy_and_aborts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, tailer, ns = self._setup(root, self.ns_grow)
            with self.assertRaises(RuntimeError):
                ns["rotate_output_file"](active, tailer, compress=True, keep_days=2)
            # a cópia parcial desta tentativa foi removida: só restam o ativo e o state
            leftovers = sorted(
                p.name for p in root.rglob("*") if p.is_file() and p.name not in ("sensor-1-9995.csv", "sensor-1-9995.csv.offset.json")
            )
            self.assertEqual([], leftovers)

    # C. CSV ativo permanece intacto após falha (não truncado)
    def test_active_csv_stays_intact_after_failed_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, tailer, ns = self._setup(root, self.ns_grow)
            with self.assertRaises(RuntimeError):
                ns["rotate_output_file"](active, tailer, compress=True, keep_days=2)
            # conteúdo original preservado + o EXTRA gravado pelo writer durante a cópia
            self.assertEqual(b"abcdefEXTRA", active.read_bytes())

    # D. arquivos antigos/rotacionados não são tocados
    def test_old_rotated_files_untouched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, tailer, ns = self._setup(root, self.ns_grow)
            old_gz = root / "sensor-1-9995-20260101-000000.csv.gz"
            old_gz.write_bytes(b"OLDGZ")
            old_ck = root / "sensor-1-9995-20260101-000000.csv.gz.processed.json"
            old_ck.write_text(json.dumps({"checkpoint_valid": True, "ingestion_complete": True}), encoding="utf-8")
            unrelated = root / "unrelated.tmp"
            unrelated.write_bytes(b"KEEP")
            with self.assertRaises(RuntimeError):
                ns["rotate_output_file"](active, tailer, compress=True, keep_days=2)
            self.assertEqual(b"OLDGZ", old_gz.read_bytes())
            self.assertEqual(b"KEEP", unrelated.read_bytes())
            self.assertTrue(old_ck.exists())

    # E. disco insuficiente -> rotação bloqueada sem criar arquivos
    def test_low_disk_space_blocks_rotation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            active, tailer, ns = self._setup(root, self.ns_low_disk)
            with self.assertRaises(RuntimeError) as ctx:
                ns["rotate_output_file"](active, tailer, compress=True, keep_days=2)
            self.assertIn("insufficient free disk space", str(ctx.exception))
            # ativo preservado (não truncado) e nenhum arquivo de rotação criado
            self.assertEqual(b"abcdef", active.read_bytes())
            leftovers = sorted(
                p.name for p in root.rglob("*") if p.is_file() and p.name not in ("sensor-1-9995.csv", "sensor-1-9995.csv.offset.json")
            )
            self.assertEqual([], leftovers)


class RotationRaceStaticTest(unittest.TestCase):
    def test_protected_rotation_markers_present_in_parser(self):
        # guarda de regressão: a correção (rotação atômica protegida) deve
        # continuar presente no fonte
        self.assertIn('"method": "copytruncate-protected"', PMACCT_SOURCE)
        self.assertIn("partial.unlink(missing_ok=True)", PMACCT_SOURCE)
        self.assertIn("os.replace(partial, rotated)", PMACCT_SOURCE)
        self.assertIn("shutil.disk_usage(output_file.parent)", PMACCT_SOURCE)
        self.assertIn("insufficient free disk space", PMACCT_SOURCE)


if __name__ == "__main__":
    unittest.main()
