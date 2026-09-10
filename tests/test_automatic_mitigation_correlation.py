import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AutomaticMitigationCorrelationGuardrailsTest(unittest.TestCase):
    """Guardrails da correlacao ALREADY_MITIGATED (frontend, via Node).

    Os casos (A-F) exercitam a logica real extraida de frontend/index.html:
    compatibilidade de connector, dimensoes obrigatorias e mitigacao
    realmente ativa (execution.status=active OU announcement advertised
    com expires_at futuro).
    """

    def test_correlation_guardrails_harness(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js não está disponível")
        harness = ROOT / "tests" / "automatic_mitigation_correlation_harness.js"
        completed = subprocess.run(
            [node, str(harness)],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        self.assertEqual(
            0,
            completed.returncode,
            (completed.stdout or "") + (completed.stderr or ""),
        )
        self.assertIn("All checks passed", completed.stdout or "")
