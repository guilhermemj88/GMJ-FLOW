#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


CONNECTED_MARKERS = ("connected to", "connected with", "connection established")
DISCONNECT_MARKERS = (
    "disconnected",
    "disconnecting",
    "connection lost",
    "connection reset",
    "peer reset",
    "session reset",
    "closing connection",
)
SHUTDOWN_MARKERS = ("sigterm", "performing shutdown", "stopped listening", "shutting down")
FLOWSPEC_MARKERS = (
    "family-allowed in-open",
    "ipv4 flow",
    "ipv4-flow",
    "afi ipv4 safi flow",
    "afi 1 safi 133",
    "flow-v4",
)
PEER_ALIAS_RE = re.compile(r"\b(?:peer|neighbor|neighbour)[-_ ]?\d+\b", re.IGNORECASE)


def run(args: list[str], timeout: float = 2.0) -> tuple[int, str]:
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        output = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part.strip())
        return completed.returncode, output
    except FileNotFoundError:
        return 127, f"{args[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, f"{args[0]} timeout"


def parse_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.isdigit():
        number = int(text)
        if number > 10_000_000_000:
            number /= 1_000_000
        return datetime.fromtimestamp(number, tz=timezone.utc)
    text = re.sub(r"^[A-Z][a-z]{2}\s+", "", text)
    text = re.sub(r"\s+UTC$", "+00:00", text, flags=re.IGNORECASE)
    text = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        match = re.match(r"(\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+)", text)
        if not match:
            return None
        try:
            parsed = datetime.fromisoformat(match.group(1))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def timestamp_text(value: datetime | None) -> str:
    return value.isoformat().replace("+00:00", "Z") if value else ""


def journal_events(output: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, raw_line in enumerate(output.splitlines()):
        line = raw_line.strip()
        if not line:
            continue
        message = line
        timestamp = None
        invocation_id = ""
        try:
            record = json.loads(line)
        except (TypeError, ValueError):
            record = None
        if isinstance(record, dict):
            message = str(record.get("MESSAGE") or "")
            timestamp = parse_timestamp(record.get("__REALTIME_TIMESTAMP"))
            invocation_id = str(record.get("_SYSTEMD_INVOCATION_ID") or record.get("INVOCATION_ID") or "").strip()
        else:
            timestamp = parse_timestamp(line)
        events.append(
            {
                "index": index,
                "timestamp": timestamp,
                "invocation_id": invocation_id,
                "message": message,
            }
        )
    return events


def event_after(left: dict[str, Any] | None, right: dict[str, Any] | None) -> bool:
    """Return whether left is later than right, using journal order as fallback."""
    if left is None:
        return False
    if right is None:
        return True
    if left.get("timestamp") and right.get("timestamp"):
        return bool(left["timestamp"] > right["timestamp"])
    return int(left.get("index") or 0) > int(right.get("index") or 0)


def event_is_current(
    event: dict[str, Any], current_invocation: str, service_started_at: datetime | None
) -> bool:
    invocation = str(event.get("invocation_id") or "")
    if current_invocation and invocation:
        return invocation == current_invocation
    if current_invocation and not invocation and service_started_at and event.get("timestamp"):
        return bool(event["timestamp"] >= service_started_at)
    if service_started_at and event.get("timestamp"):
        return bool(event["timestamp"] >= service_started_at)
    # A current invocation ID may be absent on systemd's own unit messages.
    return bool(current_invocation and not invocation)


def exabgp_evidence(
    log_output: str,
    peer_ip: str,
    current_invocation: str,
    service_started_at: datetime | None,
) -> dict[str, Any]:
    events = journal_events(log_output)
    aliases: set[str] = set()
    for event in events:
        message = str(event["message"])
        if peer_ip and peer_ip in message and event_is_current(event, current_invocation, service_started_at):
            aliases.update(match.group(0).lower() for match in PEER_ALIAS_RE.finditer(message))

    def peer_event(event: dict[str, Any]) -> bool:
        message = str(event["message"])
        lowered = message.lower()
        return bool(peer_ip and peer_ip in message) or any(alias in lowered for alias in aliases)

    connected = None
    disconnected = None
    shutdown = None
    family = None
    details: list[str] = []
    for event in events:
        lowered = str(event["message"]).lower()
        current = event_is_current(event, current_invocation, service_started_at)
        related = peer_event(event)
        matched = False
        if current and related and any(marker in lowered for marker in CONNECTED_MARKERS):
            connected = event
            matched = True
        if current and related and any(marker in lowered for marker in DISCONNECT_MARKERS):
            disconnected = event
            matched = True
        if current and any(marker in lowered for marker in SHUTDOWN_MARKERS):
            shutdown = event
            matched = True
        if current and related and any(marker in lowered for marker in FLOWSPEC_MARKERS):
            family = event
            matched = True
        if matched:
            details.append(str(event["message"])[-500:])

    invalidating = disconnected if event_after(disconnected, shutdown) else shutdown
    connected_current = bool(connected and not event_after(invalidating, connected))
    family_current = bool(family and not event_after(invalidating, family))
    return {
        "connected_current": connected_current,
        "family_current": family_current,
        "explicit_disconnect": bool(disconnected and event_after(disconnected, connected)),
        "explicit_shutdown": bool(shutdown and event_after(shutdown, connected)),
        "last_connected_at": timestamp_text(connected.get("timestamp") if connected else None),
        "last_disconnect_at": timestamp_text(disconnected.get("timestamp") if disconnected else None),
        "last_shutdown_at": timestamp_text(shutdown.get("timestamp") if shutdown else None),
        "last_family_evidence_at": timestamp_text(family.get("timestamp") if family else None),
        "source": "exabgp_journal",
        "details": details[-20:],
        "peer_aliases": sorted(aliases),
        "current_invocation_id": current_invocation,
        "service_started_at": timestamp_text(service_started_at),
    }


def fifo_reader_active(path: str, target_stat: os.stat_result) -> bool:
    """Inspect Linux process descriptors without opening or writing to the FIFO."""
    proc = Path("/proc")
    if not proc.is_dir():
        return False
    try:
        processes = list(proc.iterdir())
    except OSError:
        return False
    for process in processes:
        if not process.name.isdigit():
            continue
        fd_dir = process / "fd"
        try:
            descriptors = list(fd_dir.iterdir())
        except OSError:
            continue
        for descriptor in descriptors:
            try:
                descriptor_stat = descriptor.stat()
                if (
                    descriptor_stat.st_dev != target_stat.st_dev
                    or descriptor_stat.st_ino != target_stat.st_ino
                ):
                    continue
                fdinfo = (process / "fdinfo" / descriptor.name).read_text(errors="replace")
                flags_match = re.search(r"^flags:\s*([0-7]+)", fdinfo, flags=re.MULTILINE)
                if not flags_match:
                    continue
                access_mode = int(flags_match.group(1), 8) & getattr(os, "O_ACCMODE", 3)
                if access_mode != os.O_WRONLY:
                    return True
            except (OSError, ValueError):
                continue
    return False


def fifo_status(path: str) -> dict[str, Any]:
    exists = bool(path and os.path.exists(path))
    is_fifo = False
    reader_active = False
    error = ""
    if exists:
        try:
            target_stat = os.stat(path)
            is_fifo = stat.S_ISFIFO(target_stat.st_mode)
            if is_fifo:
                reader_active = fifo_reader_active(path, target_stat)
        except OSError as exc:
            error = str(exc)
    return {
        "path": path,
        "exists": exists,
        "is_fifo": is_fifo,
        "reader_active": reader_active,
        "ok": exists and is_fifo and reader_active,
        "error": error,
    }


def bgp_status(service: str, peer_ip: str, listen_port: int, pipe_path: str = "") -> dict[str, object]:
    service_code, service_output = run(["systemctl", "is-active", service]) if service else (1, "service not configured")
    invocation_code, invocation_output = (
        run(["systemctl", "show", service, "--property=InvocationID", "--value"])
        if service else (1, "")
    )
    started_code, started_output = (
        run(["systemctl", "show", service, "--property=ExecMainStartTimestamp", "--value"])
        if service else (1, "")
    )
    listen_code, listen_output = run(["ss", "-lntp"])
    session_code, session_output = run(["ss", "-antp"])
    log_code, log_output = (
        run(["journalctl", "-u", service, "-n", "1000", "--no-pager", "-o", "json"], timeout=4.0)
        if service else (1, "")
    )

    service_active = service_code == 0 and service_output.strip() == "active"
    listening = listen_code == 0 and any(f":{listen_port}" in line for line in listen_output.splitlines())
    tcp_established = False
    if session_code == 0:
        for line in session_output.splitlines():
            upper = line.upper()
            if "ESTAB" not in upper and "ESTABLISHED" not in upper:
                continue
            if peer_ip and peer_ip not in line:
                continue
            if f":{listen_port}" in line:
                tcp_established = True
                break

    current_invocation = invocation_output.strip() if invocation_code == 0 else ""
    service_started_at = parse_timestamp(started_output) if started_code == 0 else None
    evidence = exabgp_evidence(
        log_output if log_code == 0 else "", peer_ip, current_invocation, service_started_at
    )
    explicit_down = bool(evidence["explicit_disconnect"] or evidence["explicit_shutdown"])
    if not service_active or explicit_down or (evidence["connected_current"] and not tcp_established):
        bgp_state = "down"
    elif tcp_established and evidence["connected_current"]:
        bgp_state = "established"
    else:
        bgp_state = "not_verified"
    if bgp_state == "down":
        flowspec_state = "down"
    elif bgp_state == "established" and evidence["family_current"]:
        flowspec_state = "established"
    else:
        flowspec_state = "not_verified"

    return {
        "available": True,
        "service": {"name": service, "active": service_active, "raw": service_output},
        "listener": {"listening": listening, "expected_port": listen_port},
        "session": {"tcp_established": tcp_established, "peer_ip": peer_ip},
        "bgp_state": bgp_state,
        "flowspec_state": flowspec_state,
        "pipe": fifo_status(pipe_path),
        "evidence": evidence,
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/bgp/status":
            self.send_response(404)
            self.end_headers()
            return
        params = parse_qs(parsed.query)
        service = params.get("service", [""])[0]
        peer_ip = params.get("peer_ip", [""])[0]
        pipe_path = params.get("pipe_path", [""])[0]
        try:
            listen_port = int(params.get("listen_port", ["179"])[0])
        except ValueError:
            listen_port = 179
        payload = bgp_status(service, peer_ip, listen_port, pipe_path)
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="GMJ-FLOW optional host status agent")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
