from __future__ import annotations

import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))


class RuntimeImportsTest(unittest.TestCase):
    def test_backend_runtime_imports_and_shared_security_ai_api(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory, patch.dict(
            os.environ,
            {
                "GMJFLOW_DB_PATH": str(Path(temporary_directory) / "runtime-import.db"),
                "GMJFLOW_SECURITY_AI_ENABLED": "false",
                "GMJFLOW_ANOMALY_DETECTION_ENABLED": "false",
                "GMJFLOW_BEHAVIORAL_DETECTION_ENABLED": "false",
                "GMJFLOW_THREAT_INTEL_SCHEDULER_ENABLED": "false",
            },
            clear=False,
        ):
            for module_name in (
                "app.main",
                "app.api.threat_engine",
                "app.services.security_event_ai",
                "app.services.campaign_ai",
            ):
                self.assertIsNotNone(importlib.import_module(module_name))

        shared = importlib.import_module("app.services.security_event_ai")
        for symbol in (
            "analysis_fingerprint",
            "execute_security_ai_provider",
            "normalize_advisory_analysis",
            "security_ai_config",
        ):
            self.assertTrue(callable(getattr(shared, symbol, None)), symbol)


if __name__ == "__main__":
    unittest.main()
