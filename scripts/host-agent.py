#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import posixpath
import re
import stat
import subprocess
import time as time_module
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
DEFAULT_EXABGP_CONFIG_PATH = "/etc/exabgp/gmj-flow-ne8000.conf"
DEFAULT_EXABGP_SYSTEMD_SERVICE = "exabgp-gmj-flow.service"
DEFAULT_CLOSE_WAIT_ALERT_THRESHOLD = 5
DEFAULT_RECV_Q_ALERT_THRESHOLD = 0
MAX_LOG_READ_BYTES = 4 * 1024 * 1024
MAX_CONFIG_READ_BYTES = 1024 * 1024
PERSISTENT_FIFO_WRAPPER_PATHS = {"/usr/local/sbin/exabgp-fifo-reader.sh"}
SHELL_EXECUTABLES = {"/bin/sh", "/bin/bash", "/bin/dash", "sh", "bash", "dash"}
SYSTEMD_SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@:-]+(?:\.service)?$")


def normalize_systemd_service_name(value: Any) -> str:
    service = str(value or "").strip()
    if not service:
        service = DEFAULT_EXABGP_SYSTEMD_SERVICE
    if not SYSTEMD_SERVICE_RE.fullmatch(service):
        raise ValueError("invalid systemd service name")
    if not service.endswith(".service"):
        service = f"{service}.service"
    return service


def configured_int(
    name: str,
    default: int,
    minimum: int = 0,
    maximum: int = 1_000_000,
) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))


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


def validated_config_path(requested_path: str, configured_path: str) -> str:
    """Allow only the exact absolute config file selected by the agent operator."""
    requested = str(requested_path or configured_path or "").strip()
    configured = str(configured_path or "").strip()
    if not configured or not posixpath.isabs(configured):
        raise ValueError("configured config_path must be absolute")
    if not requested or not posixpath.isabs(requested):
        raise ValueError("config_path must be absolute")
    if "\x00" in requested or "\x00" in configured:
        raise ValueError("invalid config_path")
    normalized_requested = posixpath.normpath(requested)
    normalized_configured = posixpath.normpath(configured)
    if requested != normalized_requested or configured != normalized_configured:
        raise ValueError("config_path must be normalized")
    if normalized_requested != normalized_configured:
        raise ValueError("config_path is not configured for this Host Agent")
    return normalized_requested


def read_config_file(requested_path: str, configured_path: str) -> tuple[str, str, str]:
    """Read at most 1 MiB from the configured regular file without following links."""
    try:
        path = validated_config_path(requested_path, configured_path)
    except ValueError as exc:
        return "", str(exc), ""
    try:
        path_stat = os.lstat(path)
        if stat.S_ISLNK(path_stat.st_mode):
            return "", "configured config_path must not be a symlink", path
        if not stat.S_ISREG(path_stat.st_mode):
            return "", "configured config_path is not a regular file", path
        if path_stat.st_size > MAX_CONFIG_READ_BYTES:
            return "", "configured config_path exceeds the read limit", path
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            descriptor_stat = os.fstat(descriptor)
            if not stat.S_ISREG(descriptor_stat.st_mode):
                return "", "configured config_path is not a regular file", path
            if (
                descriptor_stat.st_dev != path_stat.st_dev
                or descriptor_stat.st_ino != path_stat.st_ino
            ):
                return "", "configured config_path changed while opening", path
            if descriptor_stat.st_size > MAX_CONFIG_READ_BYTES:
                return "", "configured config_path exceeds the read limit", path
            chunks: list[bytes] = []
            total = 0
            while total <= MAX_CONFIG_READ_BYTES:
                chunk = os.read(descriptor, MAX_CONFIG_READ_BYTES + 1 - total)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            content = b"".join(chunks)
            if len(content) > MAX_CONFIG_READ_BYTES:
                return "", "configured config_path exceeds the read limit", path
            return content.decode("utf-8", errors="replace"), "", path
        finally:
            os.close(descriptor)
    except FileNotFoundError:
        return "", "configured config_path does not exist", path
    except PermissionError:
        return "", "configured config_path is not readable", path
    except OSError:
        return "", "unable to read configured config_path", path


def exabgp_config_tokens(content: str) -> list[str]:
    """Tokenize syntax while removing comments and quoted values such as secrets."""
    sanitized: list[str] = []
    index = 0
    quote = ""
    line_comment = False
    block_comment = False
    escaped = False
    while index < len(content):
        char = content[index]
        following = content[index + 1] if index + 1 < len(content) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
                sanitized.append("\n")
            else:
                sanitized.append(" ")
        elif block_comment:
            if char == "*" and following == "/":
                sanitized.extend((" ", " "))
                block_comment = False
                index += 1
            else:
                sanitized.append("\n" if char == "\n" else " ")
        elif quote:
            sanitized.append("\n" if char == "\n" else " ")
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in {'"', "'"}:
            quote = char
            sanitized.append(" ")
        elif char == "#" or (char == "/" and following == "/"):
            line_comment = True
            sanitized.append(" ")
            if following == "/":
                sanitized.append(" ")
                index += 1
        elif char == "/" and following == "*":
            block_comment = True
            sanitized.extend((" ", " "))
            index += 1
        else:
            sanitized.append(char)
        index += 1
    return re.findall(r"[{};]|[^\s{};]+", "".join(sanitized))


def matching_brace(tokens: list[str], opening: int, limit: int | None = None) -> int | None:
    if opening >= len(tokens) or tokens[opening] != "{":
        return None
    depth = 0
    upper = len(tokens) if limit is None else min(limit, len(tokens))
    for index in range(opening, upper):
        if tokens[index] == "{":
            depth += 1
        elif tokens[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def family_config_evidence(tokens: list[str], start: int, end: int) -> tuple[bool, bool, bool]:
    family_found = False
    ipv4_flow_configured = False
    parse_valid = True
    depth = 0
    index = start
    while index < end:
        token = tokens[index]
        if token == "{":
            depth += 1
        elif token == "}":
            depth = max(0, depth - 1)
        elif depth == 0 and token.lower() == "family" and index + 1 < end and tokens[index + 1] == "{":
            family_found = True
            family_end = matching_brace(tokens, index + 1, end + 1)
            if family_end is None:
                return family_found, ipv4_flow_configured, False
            family_depth = 0
            cursor = index + 2
            while cursor < family_end:
                family_token = tokens[cursor]
                if family_token == "{":
                    family_depth += 1
                elif family_token == "}":
                    family_depth = max(0, family_depth - 1)
                elif (
                    family_depth == 0
                    and family_token.lower() == "ipv4"
                    and cursor + 2 < family_end
                    and tokens[cursor + 1].lower() == "flow"
                    and tokens[cursor + 2] == ";"
                ):
                    ipv4_flow_configured = True
                cursor += 1
            index = family_end
        index += 1
    return family_found, ipv4_flow_configured, parse_valid


def exabgp_config_evidence(content: str, peer_ip: str, config_path: str) -> dict[str, Any]:
    tokens = exabgp_config_tokens(content)
    neighbor_found = False
    family_found = False
    ipv4_flow_configured = False
    parse_valid = True
    index = 0
    while index + 2 < len(tokens):
        if (
            tokens[index].lower() == "neighbor"
            and tokens[index + 1] == peer_ip
            and tokens[index + 2] == "{"
        ):
            neighbor_found = True
            neighbor_end = matching_brace(tokens, index + 2)
            if neighbor_end is None:
                parse_valid = False
                break
            found, configured, valid = family_config_evidence(
                tokens, index + 3, neighbor_end
            )
            family_found = family_found or found
            ipv4_flow_configured = ipv4_flow_configured or configured
            parse_valid = parse_valid and valid
            index = neighbor_end
        index += 1
    return {
        "flowspec_evidence_source": "exabgp_config",
        "config_path": config_path,
        "config_readable": True,
        "config_parse_valid": parse_valid,
        "neighbor_found": neighbor_found,
        "family_block_found": family_found,
        "ipv4_flow_configured": ipv4_flow_configured,
        "config_error": "" if parse_valid else "configured neighbor block is malformed",
    }


def unavailable_config_evidence(config_path: str, error: str) -> dict[str, Any]:
    return {
        "flowspec_evidence_source": "exabgp_config",
        "config_path": config_path,
        "config_readable": False,
        "config_parse_valid": False,
        "neighbor_found": False,
        "family_block_found": False,
        "ipv4_flow_configured": False,
        "config_error": error,
    }


def empty_reader_evidence() -> dict[str, Any]:
    return {
        "reader_active": False,
        "reader_waiting_for_writer": False,
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
                    "reader_waiting_for_writer": True,
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
                        "reader_waiting_for_writer": False,
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


def socket_line_state_and_recv_q(line: str) -> tuple[str, int]:
    fields = line.split()
    known_states = {
        "ESTAB",
        "ESTABLISHED",
        "CLOSE-WAIT",
        "CLOSE_WAIT",
        "LISTEN",
        "SYN-SENT",
        "SYN-RECV",
        "TIME-WAIT",
        "LAST-ACK",
        "FIN-WAIT-1",
        "FIN-WAIT-2",
        "CLOSING",
    }
    for index, field in enumerate(fields):
        state = field.upper()
        if state not in known_states:
            continue
        try:
            recv_q = int(fields[index + 1])
        except (IndexError, ValueError):
            recv_q = 0
        return state, recv_q
    return "", 0


def socket_line_matches_peer(line: str, peer_ip: str) -> bool:
    if not peer_ip:
        return False
    return (
        re.search(
            rf"(?<![0-9A-Fa-f:.])\[?{re.escape(peer_ip)}\]?(?=[:\s])",
            line,
        )
        is not None
    )


def tcp_socket_diagnostics(
    session_output: str,
    peer_ips: list[str],
    listen_port: int,
    command_ok: bool = True,
    close_wait_threshold: int | None = None,
    recv_q_threshold: int | None = None,
) -> dict[str, Any]:
    peers = list(
        dict.fromkeys(
            str(peer or "").strip()
            for peer in peer_ips
            if str(peer or "").strip()
        )
    )
    established_peers: list[str] = []
    close_wait_by_peer = {peer: 0 for peer in peers}
    recv_q_by_peer = {peer: 0 for peer in peers}
    recv_q_total = 0
    recv_q_max = 0
    close_wait_count = 0
    for line in session_output.splitlines() if command_ok else []:
        if f":{listen_port}" not in line:
            continue
        state, recv_q = socket_line_state_and_recv_q(line)
        matching_peers = [peer for peer in peers if socket_line_matches_peer(line, peer)]
        if not matching_peers:
            continue
        recv_q_total += recv_q
        recv_q_max = max(recv_q_max, recv_q)
        for peer in matching_peers:
            recv_q_by_peer[peer] = max(recv_q_by_peer[peer], recv_q)
            if state in {"ESTAB", "ESTABLISHED"} and peer not in established_peers:
                established_peers.append(peer)
            if state in {"CLOSE-WAIT", "CLOSE_WAIT"}:
                close_wait_by_peer[peer] += 1
        if state in {"CLOSE-WAIT", "CLOSE_WAIT"}:
            close_wait_count += 1
    close_limit = (
        configured_int(
            "GMJFLOW_BGP_CLOSE_WAIT_ALERT_THRESHOLD",
            DEFAULT_CLOSE_WAIT_ALERT_THRESHOLD,
        )
        if close_wait_threshold is None
        else max(0, int(close_wait_threshold))
    )
    recv_limit = (
        configured_int(
            "GMJFLOW_BGP_RECV_Q_ALERT_THRESHOLD",
            DEFAULT_RECV_Q_ALERT_THRESHOLD,
            maximum=1_000_000_000,
        )
        if recv_q_threshold is None
        else max(0, int(recv_q_threshold))
    )
    return {
        "query_ok": bool(command_ok),
        "established_peers": established_peers,
        "missing_peers": [peer for peer in peers if peer not in established_peers],
        "close_wait_count": close_wait_count,
        "close_wait_by_peer": close_wait_by_peer,
        "close_wait_alert_threshold": close_limit,
        "close_wait_alert": close_wait_count > close_limit,
        "recv_q_total": recv_q_total,
        "recv_q_max": recv_q_max,
        "recv_q_by_peer": recv_q_by_peer,
        "recv_q_alert_threshold": recv_limit,
        "recv_q_alert": recv_q_max > recv_limit,
    }


def systemd_service_status(service: str) -> dict[str, Any]:
    code, output = run(["systemctl", "is-active", service])
    return {
        "name": service,
        "active": code == 0 and output.strip() == "active",
        "raw": output,
        "returncode": code,
    }


def listener_status(listen_port: int) -> dict[str, Any]:
    code, output = run(["ss", "-lntp"])
    listening = code == 0 and any(f":{listen_port}" in line for line in output.splitlines())
    return {
        "listening": listening,
        "expected_port": listen_port,
        "query_ok": code == 0,
        "raw": output if code != 0 else "",
    }


def bgp_status(
    service: str,
    peer_ip: str,
    listen_port: int,
    pipe_path: str = "",
    log_path: str = "",
    configured_log_path: str = DEFAULT_EXABGP_LOG_PATH,
    config_path: str = "",
    configured_config_path: str = DEFAULT_EXABGP_CONFIG_PATH,
) -> dict[str, object]:
    service = normalize_systemd_service_name(service)
    service_status = systemd_service_status(service)
    invocation_code, invocation_output = (
        run(["systemctl", "show", service, "--property=InvocationID", "--value"])
    )
    started_code, started_output = (
        run(["systemctl", "show", service, "--property=ExecMainStartTimestamp", "--value"])
    )
    listen_code, listen_output = run(["ss", "-lntp"])
    session_code, session_output = run(["ss", "-antp"])
    log_code, log_output = (
        run(["journalctl", "-u", service, "-n", "1000", "--no-pager", "-o", "json"], timeout=4.0)
    )

    service_active = bool(service_status["active"])
    listening = listen_code == 0 and any(f":{listen_port}" in line for line in listen_output.splitlines())
    socket_status = tcp_socket_diagnostics(
        session_output,
        [peer_ip],
        listen_port,
        command_ok=session_code == 0,
    )
    tcp_established = peer_ip in socket_status["established_peers"]

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
    log_evidence_source = str(evidence.get("source") or "exabgp_journal")
    config_content, config_error, accepted_config_path = read_config_file(
        config_path, configured_config_path
    )
    if config_error:
        config_evidence = unavailable_config_evidence(accepted_config_path, config_error)
    else:
        config_evidence = exabgp_config_evidence(
            config_content, peer_ip, accepted_config_path
        )
    evidence.update(config_evidence)
    evidence["source"] = f"{log_evidence_source} + exabgp_config"

    pipe = fifo_status(pipe_path)
    bgp_state = (
        "established"
        if tcp_established
        else "down"
        if session_code == 0 and bool(peer_ip)
        else "not_verified"
    )
    config_verified = bool(
        evidence["config_readable"]
        and evidence["config_parse_valid"]
        and evidence["neighbor_found"]
    )
    flowspec_ok = bool(
        config_verified
        and evidence["family_block_found"]
        and evidence["ipv4_flow_configured"]
    )
    if not config_verified:
        flowspec_state = "not_verified"
    else:
        flowspec_state = "established" if flowspec_ok else "down"
    checks = {
        "service_ok": service_active,
        "listener_ok": listening,
        "bgp_ok": tcp_established,
        "flowspec_ok": flowspec_ok,
        "pipe_ok": bool(pipe["ok"]),
    }

    return {
        "available": True,
        "service": service_status,
        "listener": {
            "listening": listening,
            "expected_port": listen_port,
            "query_ok": listen_code == 0,
        },
        "session": {
            "tcp_established": tcp_established,
            "peer_ip": peer_ip,
            **socket_status,
        },
        "bgp_state": bgp_state,
        "flowspec_state": flowspec_state,
        "checks": checks,
        **checks,
        "pipe": pipe,
        "evidence": evidence,
    }


def recovery_snapshot(
    service: str,
    peer_ips: list[str],
    listen_port: int,
    close_wait_threshold: int,
    recv_q_threshold: int,
) -> dict[str, Any]:
    service_result = systemd_service_status(service)
    listener_result = listener_status(listen_port)
    session_code, session_output = run(["ss", "-antp"])
    sockets = tcp_socket_diagnostics(
        session_output,
        peer_ips,
        listen_port,
        command_ok=session_code == 0,
        close_wait_threshold=close_wait_threshold,
        recv_q_threshold=recv_q_threshold,
    )
    return {
        "service": service_result,
        "listener": listener_result,
        "session": sockets,
        "checks": {
            "service_ok": bool(service_result["active"]),
            "listener_ok": bool(listener_result["listening"]),
            "all_peers_established": not sockets["missing_peers"],
        },
    }


def recover_bgp_sessions(
    service: str,
    peer_ips: list[str],
    listen_port: int = 179,
    close_wait_threshold: int | None = None,
    recv_q_threshold: int | None = None,
    wait_attempts: int = 20,
    wait_interval_seconds: float = 0.5,
) -> dict[str, Any]:
    normalized_service = normalize_systemd_service_name(service)
    if normalized_service != DEFAULT_EXABGP_SYSTEMD_SERVICE:
        raise ValueError(
            f"recovery is restricted to {DEFAULT_EXABGP_SYSTEMD_SERVICE}"
        )
    peers = list(
        dict.fromkeys(
            str(peer or "").strip()
            for peer in peer_ips
            if str(peer or "").strip()
        )
    )
    if not peers:
        raise ValueError("at least one peer_ip is required")
    close_limit = (
        configured_int(
            "GMJFLOW_BGP_CLOSE_WAIT_ALERT_THRESHOLD",
            DEFAULT_CLOSE_WAIT_ALERT_THRESHOLD,
        )
        if close_wait_threshold is None
        else max(0, int(close_wait_threshold))
    )
    recv_limit = (
        configured_int(
            "GMJFLOW_BGP_RECV_Q_ALERT_THRESHOLD",
            DEFAULT_RECV_Q_ALERT_THRESHOLD,
            maximum=1_000_000_000,
        )
        if recv_q_threshold is None
        else max(0, int(recv_q_threshold))
    )
    before = recovery_snapshot(
        normalized_service,
        peers,
        listen_port,
        close_limit,
        recv_limit,
    )
    restart_reasons: list[str] = []
    if not before["checks"]["service_ok"]:
        restart_reasons.append("service_inactive")
    if not before["checks"]["listener_ok"]:
        restart_reasons.append("listener_unavailable")
    if not before["checks"]["all_peers_established"]:
        restart_reasons.append("peers_missing")
    if before["session"]["close_wait_alert"]:
        restart_reasons.append("close_wait_above_threshold")
    if before["session"]["recv_q_alert"]:
        restart_reasons.append("recv_q_above_threshold")

    restart_attempted = bool(restart_reasons)
    restart_returncode = 0
    restart_output = ""
    if restart_attempted:
        restart_returncode, restart_output = run(
            ["systemctl", "restart", normalized_service],
            timeout=20.0,
        )

    after = before
    if restart_attempted and restart_returncode == 0:
        attempts = max(1, min(int(wait_attempts), 120))
        for attempt in range(attempts):
            after = recovery_snapshot(
                normalized_service,
                peers,
                listen_port,
                close_limit,
                recv_limit,
            )
            if (
                after["checks"]["service_ok"]
                and after["checks"]["listener_ok"]
                and after["checks"]["all_peers_established"]
            ):
                break
            if attempt + 1 < attempts and wait_interval_seconds > 0:
                time_module.sleep(min(float(wait_interval_seconds), 2.0))

    ok = bool(
        after["checks"]["service_ok"]
        and after["checks"]["listener_ok"]
        and after["checks"]["all_peers_established"]
        and (not restart_attempted or restart_returncode == 0)
    )
    return {
        "ok": ok,
        "service": normalized_service,
        "peer_ips": peers,
        "listen_port": listen_port,
        "restart_needed": bool(restart_reasons),
        "restart_attempted": restart_attempted,
        "restart_reasons": restart_reasons,
        "restart_returncode": restart_returncode,
        "restart_output": restart_output,
        "before": before,
        "after": after,
        "data_preserved": {
            "database": True,
            "history": True,
            "fifos": True,
            "announcements": True,
        },
    }


class Handler(BaseHTTPRequestHandler):
    configured_log_path = DEFAULT_EXABGP_LOG_PATH
    configured_config_path = DEFAULT_EXABGP_CONFIG_PATH

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
        config_path = params.get("config_path", [self.configured_config_path])[0]
        try:
            listen_port = int(params.get("listen_port", ["179"])[0])
        except ValueError:
            listen_port = 179
        try:
            payload = bgp_status(
                service,
                peer_ip,
                listen_port,
                pipe_path,
                log_path,
                self.configured_log_path,
                config_path,
                self.configured_config_path,
            )
            status_code = 200
        except ValueError as exc:
            payload = {"available": False, "error": str(exc)}
            status_code = 400
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/bgp/recover":
            self.send_response(404)
            self.end_headers()
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0 or content_length > 64 * 1024:
                raise ValueError("invalid request body size")
            request_payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
            if not isinstance(request_payload, dict):
                raise ValueError("invalid JSON payload")
            payload = recover_bgp_sessions(
                str(request_payload.get("service") or ""),
                list(request_payload.get("peer_ips") or []),
                int(request_payload.get("listen_port") or 179),
                int(
                    request_payload.get(
                        "close_wait_threshold",
                        configured_int(
                            "GMJFLOW_BGP_CLOSE_WAIT_ALERT_THRESHOLD",
                            DEFAULT_CLOSE_WAIT_ALERT_THRESHOLD,
                        ),
                    )
                ),
                int(
                    request_payload.get(
                        "recv_q_threshold",
                        configured_int(
                            "GMJFLOW_BGP_RECV_Q_ALERT_THRESHOLD",
                            DEFAULT_RECV_Q_ALERT_THRESHOLD,
                            maximum=1_000_000_000,
                        ),
                    )
                ),
            )
            status_code = 200 if payload["ok"] else 503
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            payload = {"ok": False, "error": str(exc)}
            status_code = 400
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
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
    parser.add_argument(
        "--config-path",
        default=os.getenv("GMJFLOW_EXABGP_CONFIG_PATH", DEFAULT_EXABGP_CONFIG_PATH),
        help="absolute ExaBGP config path accepted by /bgp/status",
    )
    args = parser.parse_args()
    try:
        Handler.configured_log_path = validated_log_path(args.log_path, args.log_path)
        Handler.configured_config_path = validated_config_path(
            args.config_path, args.config_path
        )
    except ValueError as exc:
        parser.error(str(exc))
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
