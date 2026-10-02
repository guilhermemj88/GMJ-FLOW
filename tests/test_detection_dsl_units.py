"""Testes de unidades e durações da DSL (Fase 3A)."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from app.services.detection_dsl import (  # noqa: E402
    DslSemanticError,
    format_quantity,
    parse_duration,
    parse_quantity,
)


class QuantityParsingTest(unittest.TestCase):
    def test_valid_quantities(self):
        cases = {
            "500": 500,
            "100k": 100_000,
            "100K": 100_000,
            "1M": 1_000_000,
            "1.5M": 1_500_000,
            "750M": 750_000_000,
            "1G": 1_000_000_000,
            "2.5G": 2_500_000_000,
            "0.8T": 800_000_000_000,
        }
        for text, expected in cases.items():
            value, display = parse_quantity(text)
            self.assertEqual(int(value), expected, text)
            self.assertEqual(display, text)

    def test_decimal_scale_not_binary(self):
        value, _ = parse_quantity("1k")
        self.assertEqual(value, 1000)
        self.assertNotEqual(value, 1024)

    def test_invalid_quantities(self):
        for text in ("1GG", "10KM", "abcM", "1.2.3M", "1 G"):
            with self.assertRaises(DslSemanticError) as ctx:
                parse_quantity(text)
            self.assertEqual(ctx.exception.code, "INVALID_UNIT", text)

    def test_format_quantity_is_friendly_and_stable(self):
        self.assertEqual(format_quantity(100_000), "100k")
        self.assertEqual(format_quantity(1_500_000), "1.5M")
        self.assertEqual(format_quantity(3_800_000_000), "3.8G")
        self.assertEqual(format_quantity(420_000), "420k")
        self.assertEqual(format_quantity(999), "999")
        self.assertEqual(format_quantity(60), "60")


class DurationParsingTest(unittest.TestCase):
    def test_durations(self):
        self.assertEqual(parse_duration("60")[0], 60)
        self.assertEqual(parse_duration("60s")[0], 60)
        self.assertEqual(parse_duration("5m")[0], 300)
        self.assertEqual(parse_duration("1h")[0], 3600)
        self.assertEqual(parse_duration("1d")[0], 86400)
        self.assertEqual(parse_duration("5m")[1], "5m")

    def test_invalid_duration(self):
        with self.assertRaises(DslSemanticError):
            parse_duration("60 s")


if __name__ == "__main__":
    unittest.main()
