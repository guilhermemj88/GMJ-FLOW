import importlib.util
import json
import stat
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "host-agent.py"
SPEC = importlib.util.spec_from_file_location("gmj_flow_host_agent", MODULE_PATH)
host_agent = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(host_agent)


def journal_record(timestamp, message, invocation="current-invocation"):
    micros = int(datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp() * 1_000_000)
    return json.dumps(
        {
            "__REALTIME_TIMESTAMP": str(micros),
            "_SYSTEMD_INVOCATION_ID": invocation,
            "MESSAGE": message,
        }
    )


class HostAgentStatusTest(unittest.TestCase):
    peer_ip = "179.189.80.0"
    pipe_path = "/run/exabgp/exabgp.in"

    def run_status(self, logs, *, tcp=True, invocation="current-invocation", pipe_exists=True, reader=True):
        def fake_run(args, timeout=2.0):
            if args[:2] == ["systemctl", "is-active"]:
                return 0, "active"
            if "--property=InvocationID" in args:
                return 0, invocation
            if "--property=ExecMainStartTimestamp" in args:
                return 0, "2026-07-21T09:59:00Z"
            if args[:2] == ["ss", "-lntp"]:
                return 0, "LISTEN 0 128 0.0.0.0:179 0.0.0.0:*"
            if args[:2] == ["ss", "-antp"]:
                return 0, f"ESTAB 0 0 192.0.2.1:179 {self.peer_ip}:179" if tcp else ""
            if args and args[0] == "journalctl":
                return 0, "\n".join(logs)
            raise AssertionError(f"Comando inesperado: {args}")

        fifo_stat = types.SimpleNamespace(st_mode=stat.S_IFIFO | 0o600, st_dev=1, st_ino=2)
        with patch.object(host_agent, "run", side_effect=fake_run), \
             patch.object(host_agent.os.path, "exists", return_value=pipe_exists), \
             patch.object(host_agent.os, "stat", return_value=fifo_stat), \
             patch.object(host_agent, "fifo_reader_active", return_value=reader):
            return host_agent.bgp_status("exabgp-gmj-flow.service", self.peer_ip, 179, self.pipe_path)

    def current_established_logs(self):
        return [
            journal_record("2026-07-21T10:00:00Z", f"connected to peer-1 with {self.peer_ip}"),
            journal_record("2026-07-21T10:00:01Z", "peer-1 family-allowed in-open ipv4 flow"),
        ]

    def test_current_bgp_and_flowspec_evidence_with_fifo_reader_are_established(self):
        status = self.run_status(self.current_established_logs())
        self.assertEqual(status["bgp_state"], "established")
        self.assertEqual(status["flowspec_state"], "established")
        self.assertTrue(status["pipe"]["ok"])
        self.assertTrue(status["pipe"]["reader_active"])
        self.assertEqual(status["evidence"]["last_connected_at"], "2026-07-21T10:00:00Z")
        self.assertEqual(status["evidence"]["last_family_evidence_at"], "2026-07-21T10:00:01Z")

    def test_tcp_without_exabgp_evidence_is_not_verified(self):
        status = self.run_status([])
        self.assertTrue(status["session"]["tcp_established"])
        self.assertEqual(status["bgp_state"], "not_verified")
        self.assertEqual(status["flowspec_state"], "not_verified")

    def test_old_connected_followed_by_shutdown_is_down(self):
        logs = self.current_established_logs() + [
            journal_record("2026-07-21T10:02:00Z", "performing shutdown after SIGTERM")
        ]
        status = self.run_status(logs)
        self.assertEqual(status["bgp_state"], "down")
        self.assertEqual(status["flowspec_state"], "down")
        self.assertEqual(status["evidence"]["last_shutdown_at"], "2026-07-21T10:02:00Z")

    def test_connected_from_previous_process_is_not_current(self):
        logs = [
            journal_record("2026-07-21T10:00:00Z", f"connected to peer-1 with {self.peer_ip}", "old-invocation"),
            journal_record("2026-07-21T10:00:01Z", "peer-1 family-allowed in-open ipv4 flow", "old-invocation"),
        ]
        status = self.run_status(logs, invocation="new-invocation")
        self.assertEqual(status["bgp_state"], "not_verified")
        self.assertEqual(status["flowspec_state"], "not_verified")
        self.assertEqual(status["evidence"]["last_connected_at"], "")

    def test_absent_pipe_is_not_ready(self):
        status = self.run_status(self.current_established_logs(), pipe_exists=False)
        self.assertFalse(status["pipe"]["ok"])
        self.assertFalse(status["pipe"]["exists"])

    def test_fifo_without_reader_is_not_ready(self):
        status = self.run_status(self.current_established_logs(), reader=False)
        self.assertTrue(status["pipe"]["is_fifo"])
        self.assertFalse(status["pipe"]["reader_active"])
        self.assertFalse(status["pipe"]["ok"])


if __name__ == "__main__":
    unittest.main()
