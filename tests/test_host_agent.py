from __future__ import annotations

import importlib.util
import json
import stat
import tempfile
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

    def run_status(
        self,
        logs,
        *,
        tcp=True,
        invocation="current-invocation",
        pipe_exists=True,
        reader=True,
        file_logs=None,
        file_mtime=None,
        started_at="2026-07-21T09:59:00Z",
        config_text=None,
        config_error="",
        service_active=True,
        service="exabgp-gmj-flow.service",
        listener=False,
        session_output=None,
        listener_required=False,
    ):
        def fake_run(args, timeout=2.0):
            if args[:2] == ["systemctl", "is-active"]:
                return (0, "active") if service_active else (3, "inactive")
            if "--property=InvocationID" in args:
                return 0, invocation
            if "--property=ExecMainStartTimestamp" in args:
                return 0, started_at
            if "--property=ExecStart" in args:
                return (
                    0,
                    f"{{ path=/usr/bin/exabgp ; argv[]=/usr/bin/exabgp "
                    f"{host_agent.DEFAULT_EXABGP_CONFIG_PATH} ; }}",
                )
            if args[:2] == ["ss", "-lntp"]:
                return (
                    0,
                    "LISTEN 0 128 0.0.0.0:179 0.0.0.0:*"
                    if listener
                    else "",
                )
            if args[:2] == ["ss", "-antp"]:
                return (
                    0,
                    session_output
                    if session_output is not None
                    else (
                        f'ESTAB 0 0 192.0.2.1:43122 {self.peer_ip}:179 '
                        f'users:(("exabgp",pid=1234,fd=9))'
                        if tcp
                        else ""
                    ),
                )
            if args and args[0] == "journalctl":
                return 0, "\n".join(logs)
            raise AssertionError(f"Comando inesperado: {args}")

        fifo_stat = types.SimpleNamespace(st_mode=stat.S_IFIFO | 0o600, st_dev=1, st_ino=2)
        reader_evidence = {
            "reader_active": reader,
            "reader_waiting_for_writer": False,
            "reader_process_pid": 4321 if reader else None,
            "reader_process_cmdline": f"/bin/cat {self.pipe_path}" if reader else "",
            "reader_detection_method": "direct_fifo_reader" if reader else "",
        }
        file_result = (
            "\n".join(file_logs or []),
            file_mtime or datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc),
            "" if file_logs is not None else "configured log_path does not exist",
        )
        if config_text is None:
            config_text = (
                f"neighbor {self.peer_ip} {{\n"
                "  family { ipv4 unicast; ipv4 flow; }\n"
                "  authentication { md5 \"never-expose-this\"; }\n"
                "}\n"
            )
        config_result = (
            "" if config_error else config_text,
            config_error,
            host_agent.DEFAULT_EXABGP_CONFIG_PATH,
        )
        with patch.object(host_agent, "run", side_effect=fake_run), \
             patch.object(host_agent.os.path, "exists", return_value=pipe_exists), \
             patch.object(host_agent.os, "stat", return_value=fifo_stat), \
             patch.object(host_agent, "fifo_reader_evidence", return_value=reader_evidence), \
             patch.object(host_agent, "read_log_file", return_value=file_result), \
             patch.object(host_agent, "read_config_file", return_value=config_result):
            return host_agent.bgp_status(
                service,
                self.peer_ip,
                179,
                self.pipe_path,
                host_agent.DEFAULT_EXABGP_LOG_PATH,
                host_agent.DEFAULT_EXABGP_LOG_PATH,
                host_agent.DEFAULT_EXABGP_CONFIG_PATH,
                host_agent.DEFAULT_EXABGP_CONFIG_PATH,
                listener_required,
            )

    def current_established_logs(self):
        return [
            journal_record("2026-07-21T10:00:00Z", f"connected to peer-1 with {self.peer_ip}"),
            journal_record("2026-07-21T10:00:01Z", "peer-1 family-allowed in-open ipv4 flow"),
        ]

    def test_current_bgp_and_flowspec_evidence_with_fifo_reader_are_established(self):
        logs = [journal_record("2026-07-21T10:00:00Z", f"connected to peer-1 with {self.peer_ip}")]
        status = self.run_status(logs)
        self.assertEqual(status["bgp_state"], "established")
        self.assertEqual(status["flowspec_state"], "established")
        self.assertFalse(status["listener_ok"])
        self.assertTrue(status["ready"])
        self.assertTrue(status["transport_ready"])
        self.assertTrue(status["pipes"]["ok"])
        self.assertTrue(status["pipes"]["reader_active"])
        self.assertEqual(status["evidence"]["last_connected_at"], "2026-07-21T10:00:00Z")
        self.assertEqual(status["evidence"]["last_family_evidence_at"], "")
        self.assertTrue(status["evidence"]["neighbor_found"])
        self.assertTrue(status["evidence"]["family_block_found"])
        self.assertTrue(status["evidence"]["ipv4_flow_configured"])
        self.assertEqual(status["evidence"]["flowspec_evidence_source"], "exabgp_config")
        self.assertEqual(status["evidence"]["source"], "exabgp_journal + exabgp_config")
        self.assertNotIn("never-expose-this", json.dumps(status))

    def test_tcp_established_is_bgp_evidence_without_log_dependency(self):
        status = self.run_status([])
        self.assertTrue(status["session"]["tcp_established"])
        self.assertEqual(status["bgp_state"], "established")
        self.assertEqual(status["flowspec_state"], "established")
        self.assertEqual(
            status["session"]["connection_directions"][self.peer_ip],
            "active",
        )
        self.assertEqual(status["session"]["active_peers"], [self.peer_ip])
        self.assertFalse(status["listener_ok"])
        self.assertTrue(status["ready"])

    def test_current_established_socket_prevents_not_verified_false_negative(self):
        status = self.run_status(
            [
                journal_record(
                    "2026-07-21T10:00:00Z",
                    f"peer {self.peer_ip} disconnected",
                    "old-invocation",
                )
            ],
            invocation="current-invocation",
        )
        self.assertEqual(status["bgp_state"], "established")
        self.assertTrue(status["bgp_ok"])
        self.assertTrue(status["ready"])

    def test_socket_for_another_peer_does_not_satisfy_requested_neighbor(self):
        status = self.run_status(
            [],
            session_output="ESTAB 0 0 192.0.2.1:43122 203.0.113.9:179",
        )
        self.assertEqual(status["bgp_state"], "down")
        self.assertFalse(status["bgp_ok"])
        self.assertFalse(status["ready"])

    def test_close_wait_above_threshold_blocks_readiness_and_reports_recv_q(self):
        close_wait = "\n".join(
            f"CLOSE-WAIT {index + 1} 0 192.0.2.1:{44000 + index} {self.peer_ip}:179"
            for index in range(host_agent.DEFAULT_CLOSE_WAIT_ALERT_THRESHOLD + 1)
        )
        status = self.run_status(
            [],
            session_output=(
                f"ESTAB 128 0 192.0.2.1:43122 {self.peer_ip}:179\n"
                f"{close_wait}"
            ),
        )
        self.assertTrue(status["bgp_ok"])
        self.assertTrue(status["session"]["close_wait_alert"])
        self.assertEqual(status["session"]["close_wait_count"], 6)
        self.assertEqual(status["session"]["recv_q_max"], 128)
        self.assertTrue(status["session"]["recv_q_alert"])
        self.assertFalse(status["close_wait_ok"])
        self.assertFalse(status["ready"])

    def test_bgp_down_is_not_ready_even_when_config_and_fifo_are_valid(self):
        status = self.run_status([], tcp=False)
        self.assertFalse(status["bgp_ok"])
        self.assertTrue(status["flowspec_ok"])
        self.assertTrue(status["pipe_ok"])
        self.assertFalse(status["ready"])

    def test_host_agent_exposes_only_canonical_pipes_schema(self):
        status = self.run_status([])
        self.assertIn("pipes", status)
        self.assertNotIn("pipe", status)

    def test_empty_journal_uses_current_log_file_events(self):
        status = self.run_status(
            [],
            file_logs=[
                f"2026-07-21 10:00:00Z | connected to peer-1 with {self.peer_ip}",
                "2026-07-21 10:00:01Z | peer-1 family-allowed in-open ipv4 flow",
            ],
        )
        self.assertEqual(status["bgp_state"], "established")
        self.assertEqual(status["flowspec_state"], "established")
        self.assertEqual(status["evidence"]["source"], "exabgp_log_file + exabgp_config")

    def test_old_log_does_not_override_current_established_tcp(self):
        status = self.run_status(
            [],
            started_at="2026-07-21T10:00:00Z",
            file_logs=[f"2026-07-21 09:58:00Z | connected to peer-1 with {self.peer_ip}"],
        )
        self.assertEqual(status["bgp_state"], "established")
        self.assertEqual(status["flowspec_state"], "established")
        self.assertEqual(status["evidence"]["last_connected_at"], "")

    def test_shutdown_log_does_not_override_current_established_tcp(self):
        status = self.run_status(
            [],
            file_logs=[
                f"2026-07-21 10:00:00Z | connected to peer-1 with {self.peer_ip}",
                "2026-07-21 10:00:01Z | peer-1 family-allowed in-open ipv4 flow",
                "2026-07-21 10:02:00Z | performing shutdown after SIGTERM",
            ],
        )
        self.assertEqual(status["bgp_state"], "established")
        self.assertEqual(status["flowspec_state"], "established")
        self.assertTrue(status["evidence"]["explicit_shutdown"])

    def test_time_only_log_timestamp_is_correlated_to_current_start(self):
        with patch.object(host_agent, "local_timezone", return_value=timezone.utc):
            status = self.run_status(
                [],
                started_at="2026-07-21T09:59:00Z",
                file_mtime=datetime(2026, 7, 21, 10, 5, tzinfo=timezone.utc),
                file_logs=[
                    f"10:00:00 | connected to peer-1 with {self.peer_ip}",
                    "10:00:01 | peer-1 family-allowed in-open ipv4 flow",
                ],
            )
        self.assertEqual(status["bgp_state"], "established")
        self.assertEqual(status["flowspec_state"], "established")
        self.assertEqual(status["evidence"]["last_connected_at"], "2026-07-21T10:00:00Z")

    def test_journal_shutdown_does_not_override_current_established_tcp(self):
        logs = self.current_established_logs() + [
            journal_record("2026-07-21T10:02:00Z", "performing shutdown after SIGTERM")
        ]
        status = self.run_status(logs)
        self.assertEqual(status["bgp_state"], "established")
        self.assertEqual(status["flowspec_state"], "established")
        self.assertEqual(status["evidence"]["last_shutdown_at"], "2026-07-21T10:02:00Z")

    def test_previous_process_log_does_not_override_current_established_tcp(self):
        logs = [
            journal_record("2026-07-21T10:00:00Z", f"connected to peer-1 with {self.peer_ip}", "old-invocation"),
            journal_record("2026-07-21T10:00:01Z", "peer-1 family-allowed in-open ipv4 flow", "old-invocation"),
        ]
        status = self.run_status(logs, invocation="new-invocation")
        self.assertEqual(status["bgp_state"], "established")
        self.assertEqual(status["flowspec_state"], "established")
        self.assertEqual(status["evidence"]["last_connected_at"], "")

    def test_absent_pipe_is_not_ready(self):
        status = self.run_status(self.current_established_logs(), pipe_exists=False)
        self.assertFalse(status["pipes"]["ok"])
        self.assertFalse(status["pipes"]["exists"])
        self.assertFalse(status["ready"])

    def test_fifo_without_reader_is_not_ready(self):
        status = self.run_status(self.current_established_logs(), reader=False)
        self.assertTrue(status["pipes"]["is_fifo"])
        self.assertFalse(status["pipes"]["reader_active"])
        self.assertFalse(status["pipes"]["ok"])
        self.assertEqual(status["flowspec_state"], "established")
        self.assertFalse(status["ready"])

    def test_service_inactive_does_not_reclassify_bgp_or_flowspec(self):
        status = self.run_status(
            self.current_established_logs(),
            service_active=False,
        )
        self.assertFalse(status["service_ok"])
        self.assertTrue(status["bgp_ok"])
        self.assertTrue(status["flowspec_ok"])
        self.assertEqual(status["bgp_state"], "established")
        self.assertEqual(status["flowspec_state"], "established")
        self.assertFalse(status["ready"])

    def test_two_peers_two_fifos_share_one_normalized_service_and_are_ready(self):
        original_peer = self.peer_ip
        original_pipe = self.pipe_path
        config = """
        neighbor 179.189.80.0 { family { ipv4 unicast; ipv4 flow; } }
        neighbor 45.5.249.0 { family { ipv4 unicast; ipv4 flow; } }
        """
        try:
            results = []
            for peer, pipe, configured_service in (
                ("179.189.80.0", "/run/exabgp/exabgp.in", "exabgp-gmj-flow"),
                ("45.5.249.0", "/run/exabgp/gm-teste.in", ""),
            ):
                self.peer_ip = peer
                self.pipe_path = pipe
                with patch.object(
                    host_agent.os,
                    "write",
                    side_effect=AssertionError("consulta de status escreveu no FIFO"),
                ):
                    results.append(
                        self.run_status(
                            [
                                journal_record(
                                    "2026-07-21T10:00:00Z",
                                    f"connected to peer with {peer}",
                                )
                            ],
                            config_text=config,
                            service=configured_service,
                        )
                    )
        finally:
            self.peer_ip = original_peer
            self.pipe_path = original_pipe
        self.assertEqual(
            [item["pipes"]["path"] for item in results],
            ["/run/exabgp/exabgp.in", "/run/exabgp/gm-teste.in"],
        )
        for status in results:
            self.assertEqual(status["service"]["name"], "exabgp-gmj-flow.service")
            self.assertFalse(status["listener_ok"])
            self.assertTrue(status["bgp_ok"])
            self.assertTrue(status["flowspec_ok"])
            self.assertTrue(status["ready"])

    def test_ipv4_flow_only_in_another_neighbor_is_not_established(self):
        config = """
        neighbor 45.5.249.0 { family { ipv4 flow; } }
        neighbor 179.189.80.1 { family { ipv4 flow; } }
        """
        status = self.run_status(self.current_established_logs(), config_text=config)
        self.assertEqual(status["flowspec_state"], "not_verified")
        self.assertFalse(status["evidence"]["neighbor_found"])

    def test_commented_ipv4_flow_does_not_count(self):
        config = f"""
        neighbor {self.peer_ip} {{
          family {{
            ipv4 unicast;
            # ipv4 flow;
            // ipv4 flow;
            /* ipv4 flow; */
          }}
        }}
        """
        status = self.run_status(self.current_established_logs(), config_text=config)
        self.assertEqual(status["flowspec_state"], "down")
        self.assertTrue(status["evidence"]["family_block_found"])
        self.assertFalse(status["evidence"]["ipv4_flow_configured"])

    def test_correct_neighbor_without_family_is_unavailable(self):
        status = self.run_status(
            self.current_established_logs(),
            config_text=f"neighbor {self.peer_ip} {{ description test; }}",
        )
        self.assertEqual(status["flowspec_state"], "down")
        self.assertTrue(status["evidence"]["neighbor_found"])
        self.assertFalse(status["evidence"]["family_block_found"])

    def test_correct_neighbor_family_without_ipv4_flow_is_unavailable(self):
        status = self.run_status(
            self.current_established_logs(),
            config_text=f"neighbor {self.peer_ip} {{ family {{ ipv4 unicast; }} }}",
        )
        self.assertEqual(status["flowspec_state"], "down")
        self.assertFalse(status["evidence"]["ipv4_flow_configured"])
        self.assertFalse(status["ready"])

    def test_ipv4_flow_outside_family_does_not_count(self):
        status = self.run_status(
            self.current_established_logs(),
            config_text=f"neighbor {self.peer_ip} {{ ipv4 flow; family {{ ipv4 unicast; }} }}",
        )
        self.assertEqual(status["flowspec_state"], "down")
        self.assertTrue(status["evidence"]["family_block_found"])
        self.assertFalse(status["evidence"]["ipv4_flow_configured"])

    def test_missing_neighbor_is_not_verified(self):
        status = self.run_status(
            self.current_established_logs(),
            config_text="neighbor 192.0.2.1 { family { ipv4 flow; } }",
        )
        self.assertEqual(status["flowspec_state"], "not_verified")
        self.assertFalse(status["evidence"]["neighbor_found"])

    def test_unreadable_config_is_not_verified(self):
        status = self.run_status(
            self.current_established_logs(), config_error="configured config_path is not readable"
        )
        self.assertEqual(status["flowspec_state"], "not_verified")
        self.assertFalse(status["evidence"]["config_readable"])

    def test_multiple_neighbors_are_parsed_independently(self):
        config = f"""
        group edge {{
          neighbor 45.5.249.0 {{ family {{ ipv4 unicast; }} }}
          neighbor {self.peer_ip} {{
            description \"braces {{ and ipv4 flow; in a secret-like string }}\";
            family {{ ipv4 unicast; ipv4 flow; }}
          }}
        }}
        """
        status = self.run_status(self.current_established_logs(), config_text=config)
        self.assertEqual(status["flowspec_state"], "established")
        self.assertTrue(status["evidence"]["neighbor_found"])
        self.assertTrue(status["evidence"]["ipv4_flow_configured"])

    def test_realistic_exabgp_config_with_nested_ipv4_flow_is_recognized(self):
        config = f"""
        process watch-42 {{
          run /bin/cat {self.pipe_path};
          encoder text;
        }}
        neighbor {self.peer_ip} {{
          router-id 192.0.2.1;
          local-address 192.0.2.1;
          local-as 64512;
          peer-as 64513;
          family {{
            ipv4 {{
              flow;
            }}
          }}
          api {{ processes [ watch-42 ]; }}
        }}
        """
        status = self.run_status([], config_text=config)
        self.assertTrue(status["evidence"]["neighbor_found"])
        self.assertTrue(status["evidence"]["family_block_found"])
        self.assertTrue(status["evidence"]["ipv4_flow_configured"])
        self.assertTrue(status["flowspec_ok"])
        self.assertTrue(status["ready"])


class HostAgentFifoReaderTest(unittest.TestCase):
    fifo_path = "/run/exabgp/gm-teste.in"

    def create_process(self, proc: Path, pid: int, arguments: list[str]) -> Path:
        process = proc / str(pid)
        (process / "fd").mkdir(parents=True)
        (process / "fdinfo").mkdir()
        (process / "cmdline").write_bytes(b"\0".join(item.encode() for item in arguments) + b"\0")
        return process

    def detect_wrapper(self, arguments: list[str]):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            self.create_process(proc, 2468, arguments)
            target_stat = types.SimpleNamespace(st_dev=1, st_ino=2)
            with patch.object(host_agent.os, "open", side_effect=AssertionError("FIFO aberto")), \
                 patch.object(host_agent.os, "write", side_effect=AssertionError("FIFO escrito")):
                return host_agent.fifo_reader_evidence(self.fifo_path, target_stat, proc)

    def test_persistent_wrapper_is_active_between_cat_reopens(self):
        evidence = self.detect_wrapper(
            ["/bin/sh", "/usr/local/sbin/exabgp-fifo-reader.sh", self.fifo_path]
        )
        self.assertTrue(evidence["reader_active"])
        self.assertEqual(evidence["reader_process_pid"], 2468)
        self.assertEqual(evidence["reader_detection_method"], "persistent_wrapper")
        self.assertEqual(
            evidence["reader_process_cmdline"],
            f"/bin/sh /usr/local/sbin/exabgp-fifo-reader.sh {self.fifo_path}",
        )

    def test_similarly_named_unrelated_process_is_not_a_reader(self):
        evidence = self.detect_wrapper(
            ["/bin/sh", "/usr/local/sbin/exabgp-fifo-reader.sh-copy", self.fifo_path]
        )
        self.assertFalse(evidence["reader_active"])

    def test_wrapper_for_different_fifo_is_not_a_reader(self):
        evidence = self.detect_wrapper(
            ["/bin/sh", "/usr/local/sbin/exabgp-fifo-reader.sh", "/run/exabgp/other.in"]
        )
        self.assertFalse(evidence["reader_active"])

    def test_direct_fifo_reader_returns_process_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            proc = Path(directory)
            process = self.create_process(proc, 1357, ["/bin/cat", self.fifo_path])
            descriptor = process / "fd" / "3"
            descriptor.write_bytes(b"")
            (process / "fdinfo" / "3").write_text("flags:\t00000000\n", encoding="utf-8")
            target_stat = descriptor.stat()
            evidence = host_agent.fifo_reader_evidence(self.fifo_path, target_stat, proc)
        self.assertTrue(evidence["reader_active"])
        self.assertEqual(evidence["reader_process_pid"], 1357)
        self.assertEqual(evidence["reader_detection_method"], "direct_fifo_reader")
        self.assertEqual(evidence["reader_process_cmdline"], f"/bin/cat {self.fifo_path}")


class HostAgentRecoveryTest(unittest.TestCase):
    peers = ["179.189.80.0", "45.5.249.0"]

    def test_active_mode_recovery_is_healthy_without_local_listener(self):
        commands = []

        def fake_run(args, timeout=2.0):
            commands.append(args)
            if args[:2] == ["systemctl", "is-active"]:
                return 0, "active"
            if args[:2] == ["ss", "-lntp"]:
                return 0, ""
            if args[:2] == ["ss", "-antp"]:
                return 0, "\n".join(
                    f"ESTAB 0 0 192.0.2.10:{43000 + index} {peer}:179"
                    for index, peer in enumerate(self.peers)
                )
            raise AssertionError(f"Comando inesperado: {args}")

        with patch.object(host_agent, "run", side_effect=fake_run):
            result = host_agent.recover_bgp_sessions(
                "exabgp-gmj-flow",
                self.peers,
                listener_required=False,
                wait_interval_seconds=0,
            )
        self.assertTrue(result["ok"])
        self.assertTrue(result["transport_ready"])
        self.assertFalse(result["before"]["checks"]["listener_ok"])
        self.assertFalse(result["restart_attempted"])
        self.assertNotIn("listener_unavailable", result["restart_reasons"])

    def test_healthy_manual_recovery_does_not_restart_service(self):
        commands = []

        def fake_run(args, timeout=2.0):
            commands.append(args)
            if args[:2] == ["systemctl", "is-active"]:
                return 0, "active"
            if args[:2] == ["ss", "-lntp"]:
                return 0, "LISTEN 0 128 0.0.0.0:179 0.0.0.0:*"
            if args[:2] == ["ss", "-antp"]:
                return 0, "\n".join(
                    f"ESTAB 0 0 192.0.2.10:179 {peer}:50000"
                    for peer in self.peers
                )
            raise AssertionError(f"Comando inesperado: {args}")

        with patch.object(host_agent, "run", side_effect=fake_run):
            result = host_agent.recover_bgp_sessions(
                "exabgp-gmj-flow",
                self.peers,
                wait_interval_seconds=0,
            )
        self.assertTrue(result["ok"])
        self.assertFalse(result["restart_attempted"])
        self.assertNotIn(
            ["systemctl", "restart", "exabgp-gmj-flow.service"],
            commands,
        )

    def test_manual_recovery_restarts_only_shared_service_for_close_wait_alert(self):
        commands = []
        restarted = {"value": False}

        def fake_run(args, timeout=2.0):
            commands.append(args)
            if args[:2] == ["systemctl", "is-active"]:
                return 0, "active"
            if args[:2] == ["systemctl", "restart"]:
                restarted["value"] = True
                return 0, ""
            if args[:2] == ["ss", "-lntp"]:
                return 0, "LISTEN 0 128 0.0.0.0:179 0.0.0.0:*"
            if args[:2] == ["ss", "-antp"]:
                established = "\n".join(
                    f"ESTAB 0 0 192.0.2.10:179 {peer}:50000"
                    for peer in self.peers
                )
                if restarted["value"]:
                    return 0, established
                return 0, (
                    established
                    + "\nCLOSE-WAIT 32 0 192.0.2.10:179 179.189.80.0:50001"
                )
            raise AssertionError(f"Comando inesperado: {args}")

        with patch.object(host_agent, "run", side_effect=fake_run):
            result = host_agent.recover_bgp_sessions(
                "exabgp-gmj-flow.service",
                self.peers,
                close_wait_threshold=0,
                wait_interval_seconds=0,
            )
        self.assertTrue(result["ok"])
        self.assertEqual(
            commands.count(
                ["systemctl", "restart", "exabgp-gmj-flow.service"]
            ),
            1,
        )
        self.assertIn("close_wait_above_threshold", result["restart_reasons"])
        self.assertEqual(result["before"]["session"]["close_wait_count"], 1)
        self.assertEqual(result["after"]["session"]["close_wait_count"], 0)
        self.assertTrue(all(result["data_preserved"].values()))

    def test_recovery_rejects_any_other_systemd_service(self):
        with self.assertRaises(ValueError):
            host_agent.recover_bgp_sessions(
                "another.service",
                self.peers,
                wait_interval_seconds=0,
            )


class HostAgentLogSafetyTest(unittest.TestCase):
    def test_request_cannot_select_an_unconfigured_log_file(self):
        with patch.object(host_agent.os, "lstat") as lstat_call, \
             patch.object(host_agent.os, "open") as open_call:
            output, modified_at, error = host_agent.read_log_file(
                "/etc/passwd", host_agent.DEFAULT_EXABGP_LOG_PATH
            )
        self.assertEqual(output, "")
        self.assertIsNone(modified_at)
        self.assertIn("not configured", error)
        lstat_call.assert_not_called()
        open_call.assert_not_called()

    def test_systemd_start_timestamp_with_numeric_timezone_is_parsed(self):
        parsed = host_agent.parse_timestamp("Tue 2026-07-21 09:59:00 -03")
        self.assertEqual(parsed, datetime(2026, 7, 21, 12, 59, tzinfo=timezone.utc))


class HostAgentConfigSafetyTest(unittest.TestCase):
    config_path = host_agent.DEFAULT_EXABGP_CONFIG_PATH

    def test_request_cannot_select_an_unconfigured_config_file(self):
        with patch.object(host_agent.os, "lstat") as lstat_call, \
             patch.object(host_agent.os, "open") as open_call:
            content, error, accepted = host_agent.read_config_file(
                "/etc/shadow", self.config_path
            )
        self.assertEqual(content, "")
        self.assertEqual(accepted, "")
        self.assertIn("not configured", error)
        lstat_call.assert_not_called()
        open_call.assert_not_called()

    def test_config_symlink_is_rejected_without_opening_it(self):
        link_stat = types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_size=10)
        with patch.object(host_agent.os, "lstat", return_value=link_stat), \
             patch.object(host_agent.os, "open") as open_call:
            content, error, accepted = host_agent.read_config_file(
                self.config_path, self.config_path
            )
        self.assertEqual(content, "")
        self.assertEqual(accepted, self.config_path)
        self.assertIn("symlink", error)
        open_call.assert_not_called()

    def test_oversized_config_is_rejected_without_opening_it(self):
        file_stat = types.SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_size=host_agent.MAX_CONFIG_READ_BYTES + 1,
        )
        with patch.object(host_agent.os, "lstat", return_value=file_stat), \
             patch.object(host_agent.os, "open") as open_call:
            content, error, accepted = host_agent.read_config_file(
                self.config_path, self.config_path
            )
        self.assertEqual(content, "")
        self.assertEqual(accepted, self.config_path)
        self.assertIn("read limit", error)
        open_call.assert_not_called()

    def test_config_read_is_bounded_read_only_and_never_writes(self):
        config = b"neighbor 179.189.80.0 { family { ipv4 flow; } }"
        file_stat = types.SimpleNamespace(
            st_mode=stat.S_IFREG | 0o600,
            st_size=len(config),
            st_dev=10,
            st_ino=20,
        )
        with patch.object(host_agent.os, "lstat", return_value=file_stat), \
             patch.object(host_agent.os, "open", return_value=99) as open_call, \
             patch.object(host_agent.os, "fstat", return_value=file_stat), \
             patch.object(host_agent.os, "read", side_effect=[config, b""]) as read_call, \
             patch.object(host_agent.os, "close"), \
             patch.object(host_agent.os, "write") as write_call:
            content, error, accepted = host_agent.read_config_file(
                self.config_path, self.config_path
            )
        self.assertEqual(content, config.decode())
        self.assertEqual(error, "")
        self.assertEqual(accepted, self.config_path)
        self.assertEqual(
            open_call.call_args[0][1] & getattr(host_agent.os, "O_ACCMODE", 3),
            host_agent.os.O_RDONLY,
        )
        self.assertEqual(read_call.call_args_list[0][0], (99, host_agent.MAX_CONFIG_READ_BYTES + 1))
        write_call.assert_not_called()

    def test_systemd_exec_start_identifies_the_current_exabgp_config(self):
        output = (
            "{ path=/usr/bin/exabgp ; argv[]=/usr/bin/exabgp "
            "/etc/exabgp/gmj-flow.conf ; ignore_errors=no ; }"
        )
        self.assertEqual(
            host_agent.exabgp_config_paths_from_exec_start(output),
            ["/etc/exabgp/gmj-flow.conf"],
        )
        self.assertEqual(
            host_agent.validated_config_path(
                "/etc/exabgp/gmj-flow.conf",
                self.config_path,
                ["/etc/exabgp/gmj-flow.conf"],
            ),
            "/etc/exabgp/gmj-flow.conf",
        )


class HostAgentAuthTest(unittest.TestCase):
    def test_token_comparison_is_constant_time_and_strict(self):
        self.assertTrue(host_agent.token_is_valid("secret", "secret"))
        self.assertFalse(host_agent.token_is_valid("secret", "Secret"))
        self.assertFalse(host_agent.token_is_valid("", "secret"))
        self.assertFalse(host_agent.token_is_valid("secret", ""))

    def test_bearer_and_custom_header_are_extracted(self):
        bearer = types.SimpleNamespace(headers={"Authorization": "Bearer abc123"})
        self.assertEqual("abc123", host_agent.request_bearer_token(bearer))
        custom = types.SimpleNamespace(headers={"X-GMJFLOW-Host-Agent-Token": "tok2"})
        self.assertEqual("tok2", host_agent.request_bearer_token(custom))
        none = types.SimpleNamespace(headers={})
        self.assertEqual("", host_agent.request_bearer_token(none))

    def test_configured_token_reads_environment(self):
        with patch.dict(host_agent.os.environ, {"GMJFLOW_HOST_AGENT_TOKEN": "env-secret"}):
            self.assertEqual("env-secret", host_agent.configured_token())


class HostAgentReadOnlySurfaceTest(unittest.TestCase):
    SOURCE = MODULE_PATH.read_text(encoding="utf-8")

    def _block(self, start_marker, end_marker):
        start = self.SOURCE.index(start_marker)
        return self.SOURCE[start:self.SOURCE.index(end_marker, start)]

    def test_get_status_requires_authorization(self):
        block = self._block("    def do_GET", "    def do_POST")
        self.assertIn("_authorized()", block)
        self.assertIn("401", block)

    def test_post_recover_is_gated_by_enable_recovery(self):
        block = self._block("    def do_POST", "    def log_message")
        self.assertIn("recovery_enabled", block)
        self.assertIn("403", block)
        self.assertIn("recovery disabled on this read-only host agent", block)

    def test_main_refuses_to_start_without_token(self):
        block = self._block("def main()", "server = ThreadingHTTPServer")
        self.assertIn("GMJFLOW_HOST_AGENT_TOKEN is required", block)
        self.assertIn("if not args.token", block)


if __name__ == "__main__":
    unittest.main()
