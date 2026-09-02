from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MAIN_PATH = ROOT / "backend" / "app" / "main.py"
MAIN_SOURCE = MAIN_PATH.read_text(encoding="utf-8")


def load_readiness_definitions() -> dict[str, Any]:
    """Extract only the readiness functions from main.py without importing it."""
    tree = ast.parse(MAIN_SOURCE)
    names = {
        "normalize_systemd_service_name",
        "bgp_readiness_reason_message",
        "evaluate_bgp_connector_readiness",
    }
    selected = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    module = ast.Module(
        body=[
            ast.ImportFrom(
                module="__future__",
                names=[ast.alias(name="annotations", asname=None)],
                level=0,
            ),
            *selected,
        ],
        type_ignores=[],
    )
    ast.fix_missing_locations(module)

    def bgp_status_check_value(status, check_name, fallback=None):
        checks = status.get("checks") if isinstance(status.get("checks"), dict) else {}
        if isinstance(checks.get(check_name), bool):
            return bool(checks[check_name])
        if isinstance(status.get(check_name), bool):
            return bool(status[check_name])
        return fallback

    namespace: dict[str, Any] = {
        "Any": Any,
        "re": re,
        "clean_text": lambda value: str(value or "").strip(),
        "GMJFLOW_EXABGP_SYSTEMD_SERVICE": "exabgp-gmj-flow",
        "SYSTEMD_SERVICE_NAME_RE": re.compile(r"^[A-Za-z0-9_.@:-]+(?:\.service)?$"),
        "HTTPException": lambda **kwargs: RuntimeError(kwargs.get("detail") or "invalid"),
        "bgp_status_check_value": bgp_status_check_value,
        "normalize_bgp_pipe_payload": lambda status: dict(
            status.get("pipes") or status.get("pipe") or {}
        ),
        "compact_bgp_status_details": lambda status: {},
        "exabgp_backend_delivery_path_status": lambda input_path, output_path: {
            "delivery_path_ready": True,
        },
    }
    exec(compile(module, str(MAIN_PATH), "exec"), namespace)
    return namespace


def readiness_namespace() -> dict[str, Any]:
    namespace = load_readiness_definitions()
    return namespace


def healthy_active_connect_status(**overrides) -> dict[str, Any]:
    """A fully healthy connector in active-connect topology."""
    status: dict[str, Any] = {
        "bgp_state": "established",
        "flowspec_state": "established",
        "service": {"active": True, "check_possible": True},
        "listener": {"listening": False, "required": False},
        "session": {"tcp_established": True},
        "passive_listen_enabled": False,
        "pipes": {"ok": True, "is_fifo": True, "reader_active": True},
        "checks": {
            "service_ok": True,
            "listener_ok": True,
            "bgp_ok": True,
            "flowspec_ok": True,
            "pipe_ok": True,
            "close_wait_ok": True,
        },
    }
    status.update(overrides)
    return status


class ServiceNameNormalizationTest(unittest.TestCase):
    def setUp(self):
        self.namespace = readiness_namespace()
        self.normalize = self.namespace["normalize_systemd_service_name"]

    def test_suffix_typo_is_normalized_to_dot_service(self):
        self.assertEqual("exabgp-gmj-flow.service", self.normalize("exabgp-gmj-flow-service"))

    def test_name_without_suffix(self):
        self.assertEqual("exabgp-gmj-flow.service", self.normalize("exabgp-gmj-flow"))

    def test_name_with_suffix_unchanged(self):
        self.assertEqual("exabgp-gmj-flow.service", self.normalize("exabgp-gmj-flow.service"))

    def test_without_suffix_flag_strips_dot_service(self):
        self.assertEqual("exabgp-gmj-flow", self.normalize("exabgp-gmj-flow.service", with_suffix=False))


class ActiveConnectReadinessTest(unittest.TestCase):
    def setUp(self):
        self.namespace = readiness_namespace()
        self.evaluate = self.namespace["evaluate_bgp_connector_readiness"]

    def test_active_connect_does_not_require_local_listener(self):
        readiness = self.evaluate(healthy_active_connect_status())
        self.assertTrue(readiness["ready"])
        self.assertEqual([], readiness["failed_checks"])
        self.assertTrue(readiness["details"]["listener_informational"])
        self.assertFalse(readiness["details"]["listener_required"])
        self.assertTrue(readiness["transport_ready"])

    def test_passive_listener_down_marks_tcp_unavailable(self):
        status = healthy_active_connect_status(
            passive_listen_enabled=True,
            listener={"listening": False, "required": True},
            checks={"listener_ok": False, "bgp_ok": False},
            session={"tcp_established": False},
            bgp_state="down",
        )
        readiness = self.evaluate(status)
        self.assertFalse(readiness["ready"])
        self.assertIn("peer_bgp_down", readiness["reasons"])
        self.assertEqual("peer_down", readiness["failure_status"])

    def test_service_unverifiable_is_not_inactive(self):
        status = healthy_active_connect_status(
            service={"active": False, "check_possible": False},
            checks={"service_ok": False},
            bgp_state="not_verified",
            flowspec_state="not_verified",
            session={"tcp_established": False},
            checks2=None,
        )
        status["checks"] = {
            "service_ok": False,
            "listener_ok": True,
            "bgp_ok": False,
            "flowspec_ok": False,
            "pipe_ok": True,
            "close_wait_ok": True,
        }
        readiness = self.evaluate(status)
        self.assertFalse(readiness["ready"])
        self.assertIn("exabgp_service_unverified", readiness["reasons"])
        self.assertNotIn("exabgp_service_inactive", readiness["reasons"])
        self.assertEqual("unverified", readiness["failure_status"])

    def test_service_inactive_is_a_failure(self):
        status = healthy_active_connect_status(
            service={"active": False, "check_possible": True},
            checks={"service_ok": False},
        )
        status["checks"] = {
            "service_ok": False,
            "listener_ok": True,
            "bgp_ok": True,
            "flowspec_ok": True,
            "pipe_ok": True,
            "close_wait_ok": True,
        }
        readiness = self.evaluate(status)
        self.assertFalse(readiness["ready"])
        self.assertIn("exabgp_service_inactive", readiness["reasons"])
        self.assertEqual("failed", readiness["failure_status"])


class ReasonMessageTest(unittest.TestCase):
    def setUp(self):
        self.namespace = readiness_namespace()
        self.message = self.namespace["bgp_readiness_reason_message"]

    def test_unverified_service_reason_message(self):
        text = self.message("exabgp_service_unverified")
        self.assertIn("host-agent", text.lower())
        self.assertIn("nao verificavel", text.lower())

    def test_inactive_service_reason_message(self):
        text = self.message("exabgp_service_inactive")
        self.assertIn("indisponivel", text.lower())


if __name__ == "__main__":
    unittest.main()
