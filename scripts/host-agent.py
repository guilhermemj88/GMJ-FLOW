#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import posixpath
import re
import stat
import subprocess
from datetime import datetime, time, timedelta, timezone, tzinfo
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
EXPLICIT_LOG_TIMESTAMP_RE = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:\s*(?:Z|UTC|[+-]\d{2}:?\d{0,2}))?)",
    re.IGNORECASE,
)
TIME_ONLY_LOG_TIMESTAMP_RE = re.compile(
    r"^\s*[\[(]?(?P<timestamp>\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)(?:\s|\||[])]|$)"
)
DEFAULT_EXABGP_LOG_PATH = "/var/log/exabgp-gmj-flow.log"
MAX_LOG_READ_BYTES = 4 * 1024 * 1024
PERSISTENT_FIFO_WRAPPER_PATHS = {"/usr/local/sbin/exabgp-fifo-reader.sh"}
SHELL_EXECUTABLES = {"/bin/sh", "/bin/bash", "/bin/dash", "sh", "bash", "dash"}


def run(args: list[str], timeout: float = 2.0) -> tuple[int, str]:
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        output = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part.strip())
        return completed.returncode, output
    except FileNotFoundError:
        return 127, f"{args[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, f"{args[0]} timeout"


def parse_timestamp(value: Any, default_timezone: tzinfo = timezone.utc) -> datetime | None:
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
    text = re.sub(
        r"\s+([+-]\d{2})(?::?(\d{2}))?$",
        lambda match: f"{match.group(1)}:{match.group(2) or '00'}",
        text,
    )
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
        parsed = parsed.replace(tzinfo=default_timezone)
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


def local_timezone() -> tzinfo:
    return datetime.now().astimezone().tzinfo or timezone.utc


def _time_from_log(value: str) -> time | None:
    normalized = value.replace(",", ".")
    try:
        return time.fromisoformat(normalized)
    except ValueError:
        return None


def log_file_events(
    output: str,
    service_started_at: datetime | None,
    log_modified_at: datetime | None,
) -> list[dict[str, Any]]:
    """Parse append-only ExaBGP logs, including the usual time-only prefix."""
    host_timezone = local_timezone()
    raw_events: list[dict[str, Any]] = []
    for index, raw_line in enumerate(output.splitlines()):
        message = raw_line.strip()
        if not message:
            continue
        timestamp = None
        time_only = None
        explicit_match = EXPLICIT_LOG_TIMESTAMP_RE.search(message)
        if explicit_match:
            timestamp = parse_timestamp(explicit_match.group("timestamp"), host_timezone)
        else:
            time_match = TIME_ONLY_LOG_TIMESTAMP_RE.match(message)
            if time_match:
                time_only = _time_from_log(time_match.group("timestamp"))
        raw_events.append(
            {
                "index": index,
                "timestamp": timestamp,
                "time_only": time_only,
                "invocation_id": "",
                "requires_timestamp": True,
                "message": message,
            }
        )

    # ExaBGP commonly logs only HH:MM:SS. Walk backwards from the file mtime
    # (or current time) and roll over midnight according to append order.
    anchor = (log_modified_at or datetime.now(timezone.utc)).astimezone(host_timezone)
    future_tolerance = timedelta(minutes=5)
    for event in reversed(raw_events):
        if event["timestamp"]:
            anchor = event["timestamp"].astimezone(host_timezone)
            continue
        parsed_time = event.pop("time_only", None)
        if parsed_time is None:
            continue
        candidate = datetime.combine(anchor.date(), parsed_time, tzinfo=host_timezone)
        while candidate > anchor + future_tolerance:
            candidate -= timedelta(days=1)
        event["timestamp"] = candidate.astimezone(timezone.utc)
        anchor = candidate

    for event in raw_events:
        event.pop("time_only", None)
    return raw_events


def event_after(left: dict[str, Any] | None, right: dict[str, Any] | None) -> bool:
    """Return whether left is later than right, using journal order as fallback."""
    if left is None:
        return False
    if right is None:
        return True
    if left.get("timestamp") and right.get("timestamp"):
        if left["timestamp"] != right["timestamp"]:
            return bool(left["timestamp"] > right["timestamp"])
    return int(left.get("index") or 0) > int(right.get("index") or 0)


def event_is_current(
    event: dict[str, Any], current_invocation: str, service_started_at: datetime | None
) -> bool:
    if event.get("requires_timestamp"):
        return bool(
            service_started_at
            and event.get("timestamp")
            and event["timestamp"] >= service_started_at
        )
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
    *,
    source: str = "exabgp_journal",
    events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    parsed_events = events if events is not None else journal_events(log_output)
    aliases: set[str] = set()
    for event in parsed_events:
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
    for event in parsed_events:
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
    family_current = bool(
        connected_current
        and family
        and not event_after(connected, family)
        and not event_after(invalidating, family)
    )
    return {
        "connected_current": connected_current,
        "family_current": family_current,
        "explicit_disconnect": bool(disconnected and event_after(disconnected, connected)),
        "explicit_shutdown": bool(shutdown and event_after(shutdown, connected)),
        "last_connected_at": timestamp_text(connected.get("timestamp") if connected else None),
        "last_disconnect_at": timestamp_text(disconnected.get("timestamp") if disconnected else None),
        "last_shutdown_at": timestamp_text(shutdown.get("timestamp") if shutdown else None),
        "last_family_evidence_at": timestamp_text(family.get("timestamp") if family else None),
        "source": source,
        "details": details[-20:],
        "peer_aliases": sorted(aliases),
        "current_invocation_id": current_invocation,
        "service_started_at": timestamp_text(service_started_at),
    }


def validated_log_path(requested_path: str, configured_path: str) -> str:
    """Allow only the exact absolute log file selected by the agent operator."""
    requested = str(requested_path or configured_path or "").strip()
    configured = str(configured_path or "").strip()
    if not configured or not posixpath.isabs(configured):
        raise ValueError("configured log_path must be absolute")
    if not requested or not posixpath.isabs(requested):
        raise ValueError("log_path must be absolute")
    if "\x00" in requested or "\x00" in configured:
        raise ValueError("invalid log_path")
    normalized_requested = posixpath.normpath(requested)
    normalized_configured = posixpath.normpath(configured)
    if requested != normalized_requested or configured != normalized_configured:
        raise ValueError("log_path must be normalized")
    if normalized_requested != normalized_configured:
        raise ValueError("log_path is not configured for this Host Agent")
    return normalized_requested


def read_log_file(requested_path: str, configured_path: str) -> tuple[str, datetime | None, str]:
    """Read a bounded regular file without following links or invoking a shell."""
    try:
        path = validated_log_path(requested_path, configured_path)
    except ValueError as exc:
        return "", None, str(exc)
    try:
        path_stat = os.lstat(path)
        if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode):
            return "", None, "configured log_path is not a regular file"
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            descriptor_stat = os.fstat(descriptor)
            if not stat.S_ISREG(descriptor_stat.st_mode):
                return "", None, "configured log_path is not a regular file"
            if (
                descriptor_stat.st_dev != path_stat.st_dev
                or descriptor_stat.st_ino != path_stat.st_ino
            ):
                return "", None, "configured log_path changed while opening"
            if descriptor_stat.st_size > MAX_LOG_READ_BYTES:
                os.lseek(descriptor, -MAX_LOG_READ_BYTES, os.SEEK_END)
            content = os.read(descriptor, MAX_LOG_READ_BYTES).decode("utf-8", errors="replace")
            modified_at = datetime.fromtimestamp(descriptor_stat.st_mtime, tz=timezone.utc)
            return content, modified_at, ""
        finally:
            os.close(descriptor)
    except FileNotFoundError:
        return "", None, "configured log_path does not exist"
    except OSError as exc:
        return "", None, str(exc)


def empty_reader_evidence() -> dict[str, Any]:
    return {
        "reader_active": False,
        "reader_process_pid": None,
        "reader_process_cmdline": "",
        "reader_detection_method": "",
    }


def process_cmdline(process: Path) -> tuple[list[str], str]:
    try:
        raw = (process / "cmdline").read_bytes()
    except OSError:
        return [], ""
    arguments = [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]
    return arguments, " ".join(arguments)


def persistent_fifo_wrapper(arguments: list[str], fifo_path: str) -> bool:
    if not arguments or fifo_path not in arguments:
        return False
    executable = arguments[0]
    if executable in PERSISTENT_FIFO_WRAPPER_PATHS:
        wrapper_index = 0
    elif executable in SHELL_EXECUTABLES and len(arguments) > 1:
        wrapper_index = 1
    else:
        return False
    if arguments[wrapper_index] not in PERSISTENT_FIFO_WRAPPER_PATHS:
        return False
    # The path must be a complete argv item following the known wrapper, never
    # a substring embedded in a command or in another FIFO name.
    return fifo_path in arguments[wrapper_index + 1 :]


def fifo_reader_evidence(
    path: str,
    target_stat: os.stat_result,
    proc: Path | None = None,
) -> dict[str, Any]:
    """Inspect /proc read-only; never open the FIFO itself."""
    proc = proc or Path("/proc")
    if not proc.is_dir():
        return empty_reader_evidence()
    try:
        processes = list(proc.iterdir())
    except OSError:
        return empty_reader_evidence()
    wrapper_matches: list[dict[str, Any]] = []
    for process in processes:
        if not process.name.isdigit():
            continue
        arguments, cmdline = process_cmdline(process)
        if persistent_fifo_wrapper(arguments, path):
            wrapper_matches.append(
                {
                    "reader_active": True,
                    "reader_process_pid": int(process.name),
                    "reader_process_cmdline": cmdline,
                    "reader_detection_method": "persistent_wrapper",
                }
            )
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
                    return {
                        "reader_active": True,
                        "reader_process_pid": int(process.name),
                        "reader_process_cmdline": cmdline,
                        "reader_detection_method": "direct_fifo_reader",
                    }
            except (OSError, ValueError):
                continue
    if wrapper_matches:
        return sorted(wrapper_matches, key=lambda item: item["reader_process_pid"])[0]
    return empty_reader_evidence()


def fifo_status(path: str) -> dict[str, Any]:
    exists = bool(path and os.path.exists(path))
    is_fifo = False
    reader = empty_reader_evidence()
    error = ""
    if exists:
        try:
            target_stat = os.stat(path)
            is_fifo = stat.S_ISFIFO(target_stat.st_mode)
            if is_fifo:
                reader = fifo_reader_evidence(path, target_stat)
        except OSError as exc:
            error = str(exc)
    return {
        "path": path,
        "exists": exists,
        "is_fifo": is_fifo,
        **reader,
        "ok": exists and is_fifo and bool(reader["reader_active"]),
        "error": error,
    }


def bgp_status(
    service: str,
    peer_ip: str,
    listen_port: int,
    pipe_path: str = "",
    log_path: str = "",
    configured_log_path: str = DEFAULT_EXABGP_LOG_PATH,
) -> dict[str, object]:
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
    if not evidence["details"]:
        file_output, log_modified_at, log_error = read_log_file(log_path, configured_log_path)
        if not log_error:
            file_events = log_file_events(file_output, service_started_at, log_modified_at)
            evidence = exabgp_evidence(
                "",
                peer_ip,
                current_invocation,
                service_started_at,
                source="exabgp_log_file",
                events=file_events,
            )
        evidence["log_file_error"] = log_error
        evidence["log_path"] = (
            configured_log_path if not log_error else ""
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
    configured_log_path = DEFAULT_EXABGP_LOG_PATH

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
        log_path = params.get("log_path", [self.configured_log_path])[0]
        try:
            listen_port = int(params.get("listen_port", ["179"])[0])
        except ValueError:
            listen_port = 179
        payload = bgp_status(
            service,
            peer_ip,
            listen_port,
            pipe_path,
            log_path,
            self.configured_log_path,
        )
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
    parser.add_argument(
        "--log-path",
        default=os.getenv("GMJFLOW_EXABGP_LOG_PATH", DEFAULT_EXABGP_LOG_PATH),
        help="absolute ExaBGP log path accepted by /bgp/status",
    )
    args = parser.parse_args()
    try:
        Handler.configured_log_path = validated_log_path(args.log_path, args.log_path)
    except ValueError as exc:
        parser.error(str(exc))
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
