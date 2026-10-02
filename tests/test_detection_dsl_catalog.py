"""Testes do catalogo unico e do JSON para UI futura (Fase 3A)."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "backend") not in sys.path:
    sys.path.insert(0, str(ROOT / "backend"))

from app.services.detection_dsl import (  # noqa: E402
    CAPABILITIES,
    DEDUPE_PROFILES,
    EXAMPLES,
    FIELDS,
    GROUP_BY_ALLOWED_FIELDS,
    GROUP_BY_PRESETS,
    RESPONSE_MODES,
    catalog_json,
    parse,
    validate,
)


class CatalogJsonTest(unittest.TestCase):
    def test_catalog_is_json_serializable_with_required_keys(self):
        data = catalog_json()
        text = json.dumps(data)  # prova que e serializavel
        self.assertGreater(len(text), 1000)
        for key in (
            "ast_version",
            "sections",
            "fields",
            "operators_by_type",
            "directions",
            "decoders",
            "protocols",
            "group_by",
            "dedupe_profiles",
            "response_modes",
            "capabilities",
            "units",
            "examples",
        ):
            self.assertIn(key, data, key)

    def test_every_field_declares_metadata(self):
        data = catalog_json()
        for item in data["fields"]:
            for key in (
                "name", "text_name", "aliases", "label", "description", "type",
                "sections", "operators", "unit", "enum_values", "capability",
                "status", "introduced",
            ):
                self.assertIn(key, item, f"{item['name']}:{key}")
            self.assertIn(item["status"], ("supported", "experimental", "unavailable"))

    def test_metric_alias_points_to_canonical_field(self):
        self.assertEqual(FIELDS["packets_s"].display_name, "pps")
        self.assertEqual(FIELDS["bits_s"].display_name, "bps")
        self.assertEqual(FIELDS["flows_s"].display_name, "flows")
        self.assertIn("pps", FIELDS["packets_s"].aliases)

    def test_direction_aliases_are_documented(self):
        aliases = catalog_json()["directions"]["aliases"]
        for alias in ("receives", "download", "in", "entrando", "sends", "transmits", "upload", "out", "saindo"):
            self.assertIn(alias, aliases, alias)
        self.assertEqual(aliases["receives"], "inbound")
        self.assertEqual(aliases["transmits"], "outbound")
        self.assertEqual(aliases["saindo"], "outbound")

    def test_units_are_decimal(self):
        units = {item["suffix"]: item["factor"] for item in catalog_json()["units"]}
        self.assertEqual(units["k"], 1000)
        self.assertEqual(units["M"], 10 ** 6)
        self.assertEqual(units["G"], 10 ** 9)
        self.assertEqual(units["T"], 10 ** 12)


class CatalogConsistencyTest(unittest.TestCase):
    def test_group_by_allowed_fields_exist(self):
        for name in GROUP_BY_ALLOWED_FIELDS:
            self.assertIn(name, FIELDS, name)

    def test_capabilities_statuses(self):
        for capability in CAPABILITIES.values():
            self.assertIn(capability.status, ("supported", "experimental", "unavailable"))
        self.assertEqual(CAPABILITIES["tcp_flags"].status, "experimental")
        self.assertEqual(CAPABILITIES["flowspec_dns_block"].status, "unavailable")

    def test_registries_non_empty(self):
        self.assertTrue(GROUP_BY_PRESETS)
        self.assertTrue(DEDUPE_PROFILES)
        self.assertTrue(RESPONSE_MODES)

    def test_catalog_examples_parse_and_validate(self):
        for name, text in EXAMPLES.items():
            ast = parse(text)
            result = validate(ast)
            self.assertTrue(result.ok, f"{name}: {result.as_dict()}")


if __name__ == "__main__":
    unittest.main()
