"""Local ExaBGP session health: FSM is the source of truth.

Covers the 20 acceptance scenarios for the BGP connector readiness fix:

1.  ExaBGP running + BGP Established => session UP.
2.  Remote router not verifiable + local Established => session stays UP.
3.  Remote SSH failure does not change the local session.
4.  Remote diagnostic failure (SNMP-like) does not change the local session.
5.  ExaBGP service DOWN => session unavailable/down.
6.  ExaBGP running + BGP Idle => BGP DOWN.
7.  ExaBGP running + BGP Active => CONNECTING.
8.  TCP socket established without FSM evidence => not Established.
9.  FSM Established => Established.
10. Stale local snapshot => UNKNOWN.
11. Active/outbound mode => Listener TCP/179 = N/A.
12. Passive/listener mode => listener really required.
13. FIFO unavailable + BGP Established => session stays Established, channel degraded.
14. Remote verification NOT VERIFIED => no red flag for the session.
15. Shared service collected once per request.
16. Multiple connectors use a single snapshot per group.
17. Announcement gate vocabulary stays conservative.
18. FlowSpec availability never changes the session state.
19. Ready gate still requires channel + FlowSpec.
20. Verify-now path works with local evidence only (no remote router access).
"""

from __future__ import annotations

import ast
import importlib.util
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MAIN_PATH = ROOT / "backend" / "app" / "main.py"
MAIN_SOURCE = MAIN_PATH.read_text(encoding="utf-8")

HOST_AGENT_PATH = ROOT / "scripts" / "host-agent.py"
HOST_AGENT_SPEC = importlib.util.spec_from_file_location(
    "gmj_flow_host_agent_local_health", HOST_AGENT_PATH
)
host_agent = importlib.util.module_from_spec(HOST_AGENT_SPEC)
assert HOST_AGENT_SPEC and HOST_AGENT_SPEC.loader
HOST_AGENT_SPEC.loader.exec_module(host_agent)


def _parse_datetime_text(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _backend_delivery_stub(input_path: str, output_path: str = "") -> dict[str, Any]:
    return {
        "backend_mount_visible": False,
        "backend_pipe_in_visible": False,
        "backend_pipe_out_visible": False,
        "backend_pipe_in_is_fifo": False,
        "backend_pipe_writable": False,
        "delivery_path_ready": False,
        "reason": "backend_exabgp_pipe_unavailable",
        "reasons": ["backend_exabgp_pipe_unavailable"],
    }


AST_FUNCTIONS = (
    "normalize_bgp_session_state",
    "bgp_session_state_from_status",
    "bgp_flowspec_state_from_status",
    "bgp_flowspec_block_from_status",
    "bgp_exabgp_state_from_status",
    "pipe_explicitly_absent",
    "bgp_announcement_channel_from_status",
    "compute_bgp_delivery_evidence",
    "bgp_remote_validation_from_status",
    "bgp_snapshot_stale_seconds",
    "bgp_status_age_seconds",
    "apply_bgp_snapshot_staleness",
    "evaluate_bgp_connector_readiness",
    "bgp_readiness_reason_message",
    "normalize_bgp_pipe_payload",
    "bgp_status_check_value",
    "bgp_peer_state_from_status",
    "bgp_snapshot_group_key",
    "build_bgp_health_snapshot",
)


def main_namespace() -> dict[str, Any]:
    """Extract the readiness functions from main.py without importing FastAPI."""
    tree = ast.parse(MAIN_SOURCE)
    selected = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in AST_FUNCTIONS
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
    namespace: dict[str, Any] = {
        "Any": Any,
        "os": __import__("os"),
        "datetime": datetime,
        "timezone": timezone,
        "clean_text": lambda value: str(value or "").strip(),
        "parse_datetime_text": _parse_datetime_text,
        "bgp_check_interval_seconds": lambda: 30,
        "exabgp_backend_delivery_path_status": _backend_delivery_stub,
        "compact_bgp_status_details": lambda status: {},
        "resolve_bgp_connector_service": lambda connector: {
            "name": str(connector.get("systemd_service_name") or "exabgp-gmj-flow.service")
        },
        "GMJFLOW_EXABGP_CONFIG_PATH": "/etc/exabgp/gmj-flow-ne8000.conf",
        "GMJFLOW_HOST_AGENT_URL": "http://127.0.0.1:18080",
        "utc_now_iso": lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "host_agent_status_multi": lambda members: {
            "enabled": True,
            "available": True,
            "peers": {},
        },
    }
    exec(compile(module, str(MAIN_PATH), "exec"), namespace)
    return namespace


def healthy_status(**overrides: Any) -> dict[str, Any]:
    """Fully healthy connector: local FSM established, channel ready."""
    status: dict[str, Any] = {
        "exabgp": {
            "service_state": "running",
            "process_state": "running",
            "check_possible": True,
        },
        "bgp": {
            "state": "established",
            "source": "exabgp_journal",
            "fsm_confirmed": True,
        },
        "flowspec": {"state": "available", "source": "exabgp_config"},
        "listener": {"listening": False, "required": False},
        "session": {"tcp_established": True, "peer_ip": "179.189.80.0"},
        "pipes": {"ok": True, "is_fifo": True, "reader_active": True},
        "service": {"active": True, "check_possible": True},
    }
    status.update(overrides)
    return status


class BackendReadinessScenarioTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.namespace = main_namespace()

    def setUp(self):
        self.evaluate = self.namespace["evaluate_bgp_connector_readiness"]

    def test_01_exabgp_running_with_established_fsm_marks_session_up(self):
        readiness = self.evaluate(healthy_status())
        self.assertEqual(readiness["session_state"], "established")
        self.assertTrue(readiness["bgp_ok"])
        self.assertTrue(readiness["ready"])
        self.assertEqual(readiness["state"], "ready")
        self.assertEqual(readiness["session_health"]["state"], "ready")

    def test_02_remote_validation_unavailable_keeps_local_session_up(self):
        status = healthy_status()
        status["router_check"] = {
            "enabled": True,
            "bgp_state": "unknown",
            "flowspec_state": "unknown",
            "message": "ssh connection timed out",
        }
        readiness = self.evaluate(status)
        self.assertEqual(readiness["session_state"], "established")
        self.assertTrue(readiness["ready"])
        self.assertEqual(readiness["remote_validation"]["state"], "failed")
        self.assertNotIn("peer_bgp_not_verified", readiness["reasons"])

    def test_03_router_ssh_failure_does_not_change_local_session(self):
        status = healthy_status()
        status["router_check"] = {
            "enabled": True,
            "bgp_state": "unknown",
            "flowspec_state": "unknown",
            "message": "ssh timeout",
            "returncodes": {"bgp": 124, "flowspec": 124},
        }
        readiness = self.evaluate(status)
        self.assertEqual(readiness["session_state"], "established")
        self.assertEqual(readiness["state"], "ready")
        self.assertEqual(readiness["remote_validation"]["state"], "failed")

    def test_04_remote_diagnostic_failure_does_not_change_local_session(self):
        before = self.evaluate(healthy_status())
        status = healthy_status()
        status["snmp"] = {"available": False, "message": "SNMP timeout on sensor"}
        after = self.evaluate(status)
        self.assertEqual(before["state"], after["state"])
        self.assertEqual(before["session_state"], after["session_state"])
        self.assertTrue(after["ready"])

    def test_05_exabgp_service_down_marks_session_down(self):
        status = healthy_status(
            exabgp={
                "service_state": "inactive",
                "process_state": "stopped",
                "check_possible": True,
            },
            bgp={"state": "down", "source": "systemd", "fsm_confirmed": False},
        )
        readiness = self.evaluate(status)
        self.assertEqual(readiness["session_state"], "down")
        self.assertFalse(readiness["ready"])
        self.assertEqual(readiness["state"], "down")
        self.assertIn("exabgp_service_inactive", readiness["reasons"])

    def test_06_fsm_idle_marks_bgp_down(self):
        status = healthy_status(
            bgp={"state": "down", "source": "exabgp_journal", "fsm_confirmed": True}
        )
        readiness = self.evaluate(status)
        self.assertEqual(readiness["session_state"], "down")
        self.assertEqual(readiness["state"], "down")
        self.assertIn("peer_bgp_down", readiness["reasons"])

    def test_07_fsm_active_marks_bgp_connecting(self):
        status = healthy_status(
            bgp={"state": "connecting", "source": "exabgp_journal", "fsm_confirmed": True}
        )
        readiness = self.evaluate(status)
        self.assertEqual(readiness["session_state"], "connecting")
        self.assertFalse(readiness["ready"])
        self.assertEqual(readiness["state"], "down")
        self.assertIn("peer_bgp_connecting", readiness["reasons"])

    def test_08_tcp_established_without_fsm_is_not_established(self):
        status = healthy_status(
            bgp={"state": "unknown", "source": "none", "fsm_confirmed": False},
            session={"tcp_established": True},
        )
        readiness = self.evaluate(status)
        self.assertEqual(readiness["session_state"], "unknown")
        self.assertFalse(readiness["bgp_ok"])
        self.assertFalse(readiness["ready"])
        self.assertIn("peer_bgp_not_verified", readiness["reasons"])

    def test_09_fsm_established_marks_bgp_established(self):
        readiness = self.evaluate(
            healthy_status(
                bgp={
                    "state": "established",
                    "source": "exabgp_log_file",
                    "fsm_confirmed": True,
                }
            )
        )
        self.assertEqual(readiness["session_state"], "established")
        self.assertEqual(readiness["confirmation_level"], "peer_established")

    def test_10_stale_snapshot_degrades_to_unknown(self):
        stale = healthy_status(
            last_checked_at=(datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
        )
        downgraded = self.namespace["apply_bgp_snapshot_staleness"](stale)
        self.assertTrue(downgraded["stale"])
        self.assertEqual(downgraded["bgp"]["state"], "unknown")
        readiness = self.evaluate(downgraded)
        self.assertEqual(readiness["session_state"], "unknown")
        self.assertFalse(readiness["ready"])
        self.assertIn("peer_bgp_stale_state", readiness["reasons"])
        fresh = self.namespace["apply_bgp_snapshot_staleness"](
            healthy_status(last_checked_at=datetime.now(timezone.utc).isoformat())
        )
        self.assertFalse(fresh.get("stale", False))

    def test_11_active_connect_listener_is_not_required(self):
        readiness = self.evaluate(
            healthy_status(
                listener={"listening": False, "required": False},
                session={"tcp_established": True},
            )
        )
        self.assertTrue(readiness["ready"])
        self.assertTrue(readiness["details"]["listener_informational"])
        self.assertNotIn("tcp_listener_unavailable", readiness["reasons"])

    def test_12_passive_listener_missing_is_flagged(self):
        status = healthy_status(
            exabgp={
                "service_state": "running",
                "process_state": "running",
                "check_possible": True,
            },
            bgp={"state": "unknown", "source": "none", "fsm_confirmed": False},
            listener={"listening": False, "required": True},
            listener_required=True,
            passive_listen_enabled=True,
            session={"tcp_established": False},
        )
        readiness = self.evaluate(status)
        self.assertIn("tcp_listener_unavailable", readiness["reasons"])

    def test_13_fifo_down_keeps_session_established_and_channel_degraded(self):
        status = healthy_status(
            pipes={"ok": False, "is_fifo": False, "reader_active": False}
        )
        readiness = self.evaluate(status)
        self.assertEqual(readiness["session_state"], "established")
        self.assertEqual(readiness["session_health"]["state"], "ready")
        self.assertFalse(readiness["ready"])
        self.assertEqual(readiness["state"], "degraded")
        self.assertEqual(readiness["announcement_channel"]["state"], "down")
        self.assertIn("exabgp_pipe_unavailable", readiness["reasons"])
        self.assertNotIn("peer_bgp_not_verified", readiness["reasons"])

    def test_14_remote_not_verified_does_not_red_flag_session(self):
        status = healthy_status()
        status["router_check"] = {
            "enabled": True,
            "bgp_state": "unknown",
            "flowspec_state": "unknown",
            "message": "",
        }
        readiness = self.evaluate(status)
        self.assertEqual(readiness["remote_validation"]["state"], "not_verified")
        self.assertEqual(readiness["session_state"], "established")
        self.assertTrue(readiness["ready"])

    def test_17_announcement_gate_mapping_is_conservative(self):
        legacy = self.namespace["bgp_peer_state_from_status"]
        self.assertEqual(legacy({"bgp": {"state": "established"}}), "established")
        self.assertEqual(legacy({"bgp": {"state": "down"}}), "down")
        self.assertEqual(legacy({"bgp": {"state": "connecting"}}), "not_verified")
        self.assertEqual(legacy({"bgp": {"state": "unknown"}}), "not_verified")

    def test_18_flowspec_availability_never_changes_session_state(self):
        status = healthy_status(
            flowspec={"state": "down", "source": "exabgp_config"},
        )
        readiness = self.evaluate(status)
        self.assertEqual(readiness["session_state"], "established")
        self.assertFalse(readiness["ready"])
        self.assertIn("flowspec_down", readiness["reasons"])
        self.assertNotIn("peer_bgp_down", readiness["reasons"])

    def test_19_mitigation_readiness_still_requires_channel_and_flowspec(self):
        established = self.evaluate(healthy_status())
        self.assertTrue(established["ready"])
        degraded_channel = self.evaluate(
            healthy_status(pipes={"ok": True, "is_fifo": True, "reader_active": False})
        )
        self.assertEqual(degraded_channel["session_state"], "established")
        self.assertFalse(degraded_channel["ready"])
        self.assertEqual(
            degraded_channel["announcement_channel"]["state"], "degraded"
        )


class BackendSnapshotScenarioTest(unittest.TestCase):
    def test_16_connectors_share_one_host_agent_request_per_group(self):
        namespace = main_namespace()
        requests: list[list[str]] = []

        def fake_multi(members: list[dict[str, Any]]) -> dict[str, Any]:
            requests.append(sorted(str(item.get("peer_ip")) for item in members))
            return {"enabled": True, "available": True, "peers": {}}

        namespace["host_agent_status_multi"] = fake_multi
        connectors = [
            {
                "peer_ip": "179.189.80.0",
                "systemd_service_name": "exabgp-gmj-flow.service",
                "exabgp_config_path": "/etc/exabgp/gmj-flow-ne8000.conf",
                "exabgp_pipe_in": "/run/exabgp/exabgp.in",
            },
            {
                "peer_ip": "45.5.249.0",
                "systemd_service_name": "exabgp-gmj-flow.service",
                "exabgp_config_path": "/etc/exabgp/gmj-flow-ne8000.conf",
                "exabgp_pipe_in": "/run/exabgp/exabgp.in",
            },
            {
                "peer_ip": "203.0.113.9",
                "systemd_service_name": "exabgp-gmj-flow.service",
                "exabgp_config_path": "/etc/exabgp/gmj-flow-ne8000.conf",
                "exabgp_pipe_in": "/run/exabgp/gm-teste.in",
            },
        ]
        snapshot = namespace["build_bgp_health_snapshot"](connectors)
        self.assertEqual(len(requests), 2)
        self.assertIn(["179.189.80.0", "45.5.249.0"], requests)
        self.assertIn(["203.0.113.9"], requests)
        self.assertEqual(len(snapshot["groups"]), 2)


class HostAgentScenarioTest(unittest.TestCase):
    peer_one = "179.189.80.0"
    peer_two = "45.5.249.0"

    def fake_collector(self, logs: list[str]):
        calls: list[list[str]] = []

        def fake_run(args, timeout=2.0):
            calls.append(list(args))
            if args[:2] == ["systemctl", "is-active"]:
                return 0, "active"
            if args[:2] == ["systemctl", "show"]:
                return 0, "\n".join(
                    [
                        "InvocationID=inv-1",
                        "ExecMainStartTimestamp=2026-07-21T09:59:00Z",
                        "ExecStart=/usr/bin/exabgp /etc/exabgp/gmj-flow-ne8000.conf",
                        "MainPID=42",
                        "ActiveState=active",
                        "SubState=running",
                    ]
                )
            if args[:2] == ["ss", "-lntp"]:
                return 0, ""
            if args[:2] == ["ss", "-antp"]:
                return (
                    0,
                    "\n".join(
                        f"ESTAB 0 0 192.0.2.1:4312{index} {peer}:179 users:((\"exabgp\",pid=42,fd=9))"
                        for index, peer in enumerate((self.peer_one, self.peer_two))
                    ),
                )
            if args and args[0] == "journalctl":
                return 0, "\n".join(logs)
            return 127, "unexpected"

        return fake_run, calls

    def journal_record(self, message: str) -> str:
        micros = int(
            datetime(2026, 7, 21, 10, 0, tzinfo=timezone.utc).timestamp() * 1_000_000
        )
        return json.dumps(
            {
                "__REALTIME_TIMESTAMP": str(micros),
                "_SYSTEMD_INVOCATION_ID": "inv-1",
                "MESSAGE": message,
            }
        )

    def run_multi(self, logs: list[str]):
        fake_run, calls = self.fake_collector(logs)
        with patch.object(host_agent, "run", side_effect=fake_run), patch.object(
            host_agent,
            "read_log_file",
            return_value=("", None, "configured log_path does not exist"),
        ), patch.object(
            host_agent,
            "read_config_file",
            return_value=("", "missing config", "/etc/exabgp/gmj-flow-ne8000.conf"),
        ):
            host_agent.reset_bgp_state_registry()
            payload = host_agent.bgp_status_multi(
                "exabgp-gmj-flow.service",
                [self.peer_one, self.peer_two],
                179,
                "/run/exabgp/exabgp.in",
                host_agent.DEFAULT_EXABGP_LOG_PATH,
                host_agent.DEFAULT_EXABGP_LOG_PATH,
                "/etc/exabgp/gmj-flow-ne8000.conf",
                host_agent.DEFAULT_EXABGP_CONFIG_PATH,
                False,
            )
        return payload, calls

    def test_15_shared_service_collected_once_per_request(self):
        logs = [
            self.journal_record(f"connected to peer-1 with {self.peer_one}"),
            self.journal_record(f"connected to peer-2 with {self.peer_two}"),
        ]
        payload, calls = self.run_multi(logs)
        self.assertEqual(len([call for call in calls if call[:2] == ["systemctl", "is-active"]]), 1)
        self.assertEqual(len([call for call in calls if call[:2] == ["systemctl", "show"]]), 1)
        self.assertEqual(len([call for call in calls if call and call[0] == "journalctl"]), 1)
        self.assertEqual(len([call for call in calls if call[:2] == ["ss", "-antp"]]), 1)
        self.assertEqual(set(payload["peers"].keys()), {self.peer_one, self.peer_two})
        for peer_payload in payload["peers"].values():
            self.assertEqual(peer_payload["state"], "established")
            self.assertEqual(peer_payload["source"], "exabgp_journal + exabgp_config")

    def test_20_verify_now_uses_local_evidence_only(self):
        logs = [self.journal_record(f"connected to peer-1 with {self.peer_one}")]
        payload, calls = self.run_multi(logs)
        peer_status = payload["peers"][self.peer_one]
        self.assertEqual(peer_status["state"], "established")
        self.assertTrue(peer_status["fsm_confirmed"])
        self.assertTrue(peer_status["checks"]["bgp_ok"])
        # No ssh/SNMP/router command is issued by the local health check.
        for call in calls:
            self.assertNotIn("ssh", call[0].lower())
            self.assertNotIn("snmp", call[0].lower())
            self.assertNotIn("telnet", call[0].lower())

    def test_fsm_idle_and_disconnect_mark_down(self):
        idle_logs = [self.journal_record(f"peer {self.peer_one} state change idle")]
        payload, _calls = self.run_multi(idle_logs)
        self.assertEqual(payload["peers"][self.peer_one]["state"], "down")
        disconnect_logs = [
            self.journal_record(f"connected to peer-1 with {self.peer_one}"),
            self.journal_record(f"peer {self.peer_one} disconnected"),
        ]
        payload, _calls = self.run_multi(disconnect_logs)
        self.assertEqual(payload["peers"][self.peer_one]["state"], "down")

    def test_state_registry_exposes_previous_state_and_changed_at(self):
        logs = [self.journal_record(f"connected to peer-1 with {self.peer_one}")]
        payload, _calls = self.run_multi(logs)
        peer_status = payload["peers"][self.peer_one]
        self.assertTrue(peer_status["changed_at"])
        self.assertTrue(peer_status["last_update"])
        self.assertEqual(peer_status["state"], "established")


class SessionStateVocabularyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.namespace = main_namespace()

    def test_normalize_session_state_covers_fsm_vocabulary(self):
        normalize = self.namespace["normalize_bgp_session_state"]
        self.assertEqual(normalize("Established"), "established")
        self.assertEqual(normalize("OpenConfirm"), "connecting")
        self.assertEqual(normalize("OpenSent"), "connecting")
        self.assertEqual(normalize("Active"), "connecting")
        self.assertEqual(normalize("Connect"), "connecting")
        self.assertEqual(normalize("Idle"), "down")
        self.assertEqual(normalize("not_verified"), "unknown")
        self.assertEqual(normalize(""), "unknown")


if __name__ == "__main__":
    unittest.main()
