from __future__ import annotations

import csv
import gzip
import json
import math
import multiprocessing
import os
import re
import signal
import shutil
import time
from concurrent.futures import Executor, Future, ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Callable, Iterable


COLUMN_NAMES = [
    "flow_time",
    "sensor",
    "exporter_ip",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "proto",
    "tcp_flags",
    "input_if",
    "output_if",
    "bytes",
    "packets",
    "flow_count",
    "flow_type",
    "sample_rate",
    "flow_start",
    "flow_end",
    "duration_ms",
    "src_asn",
    "dst_asn",
    "src_as_name",
    "dst_as_name",
]

DEFAULT_CSV_FIELDS = [
    "src_host",
    "dst_host",
    "src_port",
    "dst_port",
    "proto",
    "tcpflags",
    "in_iface",
    "out_iface",
    "src_as",
    "dst_as",
    "timestamp",
    "packets",
    "bytes",
    "flows",
]

ALIASES = {
    "src_host": ("src_host", "src_ip", "ip_src", "srcaddr", "ipv4_src_addr", "ipv6_src_addr", "srcaddr6"),
    "dst_host": ("dst_host", "dst_ip", "ip_dst", "dstaddr", "ipv4_dst_addr", "ipv6_dst_addr", "dstaddr6"),
    "src_port": ("src_port", "l4_src_port", "srcport", "source_port"),
    "dst_port": ("dst_port", "l4_dst_port", "dstport", "destination_port"),
    "proto": ("proto", "protocol", "ip_proto", "protocol_identifier"),
    "tcpflags": ("tcpflags", "tcp_flags", "tcpflags_sum", "tcp_flags_sum"),
    "in_iface": ("in_iface", "input_if", "input_snmp", "ingress_if", "ifindex_in"),
    "out_iface": ("out_iface", "output_if", "output_snmp", "egress_if", "ifindex_out"),
    "packets": ("packets", "pkt", "pkts", "packet_count", "in_packets"),
    "bytes": ("bytes", "octets", "in_bytes", "byte_count"),
    "flows": ("flows", "flow_count", "records"),
    "timestamp": ("timestamp", "timestamp_start", "stamp_inserted", "stamp_updated", "first_switched", "flow_start"),
    "flow_start": ("flow_start", "timestamp_start", "flow_begin", "start_time"),
    "flow_end": ("flow_end", "timestamp_end", "flow_finish", "end_time"),
    "duration_ms": ("duration_ms", "flow_duration_ms", "duration_msec", "duration_milliseconds"),
    "sample_rate": ("sample_rate", "sampling_rate", "samplinginterval"),
    "src_as": ("src_as", "src_asn", "src_as_number", "src_asnum", "peer_src_as"),
    "dst_as": ("dst_as", "dst_asn", "dst_as_number", "dst_asnum", "peer_dst_as"),
    "src_as_name": ("src_as_name", "src_as_org", "src_as_description"),
    "dst_as_name": ("dst_as_name", "dst_as_org", "dst_as_description"),
}

KNOWN_HEADER_FIELDS = frozenset(
    alias.strip().strip('"').strip("'").lower().replace("-", "_").replace(" ", "_")
    for aliases in ALIASES.values()
    for alias in aliases
)

PROTO_BY_NAME = {
    "icmp": 1,
    "tcp": 6,
    "udp": 17,
    "gre": 47,
    "esp": 50,
    "icmpv6": 58,
}

PROTO_NAMES = {value: name.upper() for name, value in PROTO_BY_NAME.items()}

TCP_FLAG_BITS = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
)

TCP_FLAG_BY_NAME = {name.lower(): bit for bit, name in TCP_FLAG_BITS}


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


class CheckpointStatus(str, Enum):
    MISSING = "missing"
    LOADED = "loaded"
    CORRUPT = "corrupt"


class CheckpointError(RuntimeError):
    """An existing checkpoint cannot be trusted."""

    status = CheckpointStatus.CORRUPT


class ParallelParseError(RuntimeError):
    """A parser worker failed before the batch could be acknowledged."""


class ShutdownRequested(RuntimeError):
    """Clean shutdown requested before the batch INSERT started."""


@dataclass(frozen=True)
class ParserConfig:
    output_format: str
    delimiter: str
    fallback_fields: tuple[str, ...]
    headers: tuple[str, ...] | None
    sensor: str
    exporter_ip: str
    sample_rate: int


@dataclass(frozen=True)
class ParseChunk:
    index: int
    lines: tuple[str, ...]
    config: ParserConfig


@dataclass
class ParsedChunkResult:
    index: int
    rows: list[tuple]
    valid_count: int
    invalid_count: int
    errors: list[str] = field(default_factory=list)
    last_line_ts: str = ""
    parse_seconds: float = 0.0
    normalize_seconds: float = 0.0


@dataclass
class ParsedBatchResult:
    rows: list[tuple]
    valid_count: int
    invalid_count: int
    errors: list[str]
    last_line_ts: str
    headers: tuple[str, ...] | None
    chunk_count: int
    parse_seconds: float
    normalize_seconds: float
    parallel_parse_seconds: float
    preparation_seconds: float
    max_chunk_parse_seconds: float


@dataclass(frozen=True)
class BatchMetadata:
    sequence: int
    file_generation: int
    start_offset: int
    end_offset: int


@dataclass
class IngestionResult:
    parsed: ParsedBatchResult
    insert_seconds: float
    commit_seconds: float
    insert_context_reused: bool


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _parse_cpuset(value: str | None) -> int | None:
    if not value:
        return None
    cpus: set[int] = set()
    try:
        for token in value.split(","):
            token = token.strip()
            if not token:
                continue
            if "-" in token:
                first_raw, last_raw = token.split("-", 1)
                first, last = int(first_raw), int(last_raw)
                if last < first:
                    return None
                cpus.update(range(first, last + 1))
            else:
                cpus.add(int(token))
    except ValueError:
        return None
    return len(cpus) or None


def _unescape_mount_path(value: str) -> str:
    return (
        value.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def _resolve_cgroup_path(mount_point: str, mount_root: str, member_path: str) -> Path:
    mount = Path(_unescape_mount_path(mount_point))
    root = _unescape_mount_path(mount_root).rstrip("/") or "/"
    member = member_path.rstrip("/") or "/"
    if root == "/":
        relative = member.lstrip("/")
    elif member == root:
        relative = ""
    elif member.startswith(root + "/"):
        relative = member[len(root) + 1 :]
    else:
        relative = member.lstrip("/")
    return mount / relative


def _cgroup_mounts(mountinfo: str) -> list[tuple[str, str, str, set[str]]]:
    mounts: list[tuple[str, str, str, set[str]]] = []
    for line in mountinfo.splitlines():
        fields = line.split()
        try:
            separator = fields.index("-")
            fs_type = fields[separator + 1]
            if fs_type not in {"cgroup", "cgroup2"}:
                continue
            controllers = set(fields[5].split(","))
            if len(fields) > separator + 3:
                controllers.update(fields[separator + 3].split(","))
            mounts.append((fs_type, fields[3], fields[4], controllers))
        except (ValueError, IndexError):
            continue
    return mounts


def _cgroup_memberships(cgroup: str) -> tuple[str | None, dict[str, str]]:
    unified: str | None = None
    controllers: dict[str, str] = {}
    for line in cgroup.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        _, names, member_path = parts
        if not names:
            unified = member_path
            continue
        for name in names.split(","):
            controllers[name] = member_path
    return unified, controllers


def _read_inherited_cgroup_value(
    start: Path,
    mount_point: Path,
    names: Iterable[str],
    reader: Callable[[Path], str | None],
) -> str | None:
    current = start
    while True:
        for name in names:
            value = reader(current / name)
            if value:
                return value
        if current == mount_point or mount_point not in current.parents:
            return None
        current = current.parent


def _cgroup_cpu_limits(
    cgroup: str,
    mountinfo: str,
    reader: Callable[[Path], str | None],
) -> list[int]:
    limits: list[int] = []
    unified, memberships = _cgroup_memberships(cgroup)
    for fs_type, mount_root, mount_point_raw, controllers in _cgroup_mounts(mountinfo):
        mount_point = Path(_unescape_mount_path(mount_point_raw))
        if fs_type == "cgroup2" and unified is not None:
            group = _resolve_cgroup_path(mount_point_raw, mount_root, unified)
            cpuset_count = _parse_cpuset(
                _read_inherited_cgroup_value(
                    group,
                    mount_point,
                    ("cpuset.cpus.effective", "cpuset.cpus"),
                    reader,
                )
            )
            if cpuset_count:
                limits.append(cpuset_count)
            cpu_max = _read_inherited_cgroup_value(group, mount_point, ("cpu.max",), reader)
            if cpu_max:
                values = cpu_max.split()
                if len(values) >= 2 and values[0] != "max":
                    try:
                        quota, period = int(values[0]), int(values[1])
                        if quota > 0 and period > 0:
                            limits.append(max(1, math.ceil(quota / period)))
                    except ValueError:
                        pass
            continue

        if fs_type != "cgroup":
            continue
        if "cpuset" in controllers and "cpuset" in memberships:
            group = _resolve_cgroup_path(mount_point_raw, mount_root, memberships["cpuset"])
            cpuset_count = _parse_cpuset(
                _read_inherited_cgroup_value(
                    group,
                    mount_point,
                    ("cpuset.cpus.effective", "cpuset.cpus"),
                    reader,
                )
            )
            if cpuset_count:
                limits.append(cpuset_count)
        if controllers.intersection({"cpu", "cpuacct"}) and (
            "cpu" in memberships or "cpuacct" in memberships
        ):
            member = memberships.get("cpu") or memberships["cpuacct"]
            group = _resolve_cgroup_path(mount_point_raw, mount_root, member)
            quota_raw = _read_inherited_cgroup_value(
                group, mount_point, ("cpu.cfs_quota_us",), reader
            )
            period_raw = _read_inherited_cgroup_value(
                group, mount_point, ("cpu.cfs_period_us",), reader
            )
            try:
                quota, period = int(quota_raw or "-1"), int(period_raw or "0")
                if quota > 0 and period > 0:
                    limits.append(max(1, math.ceil(quota / period)))
            except ValueError:
                pass
    return limits


def effective_cpu_count(
    *,
    cpu_count: int | None = None,
    affinity_count: int | None = None,
    proc_cgroup: str | None = None,
    proc_mountinfo: str | None = None,
    reader: Callable[[Path], str | None] = _read_text,
) -> int:
    candidates = [max(1, cpu_count if cpu_count is not None else (os.cpu_count() or 1))]
    if affinity_count is None and hasattr(os, "sched_getaffinity"):
        try:
            affinity_count = len(os.sched_getaffinity(0))
        except OSError:
            affinity_count = None
    if affinity_count:
        candidates.append(max(1, affinity_count))
    if proc_cgroup is None:
        proc_cgroup = reader(Path("/proc/self/cgroup")) or ""
    if proc_mountinfo is None:
        proc_mountinfo = reader(Path("/proc/self/mountinfo")) or ""
    candidates.extend(_cgroup_cpu_limits(proc_cgroup, proc_mountinfo, reader))
    return max(1, min(candidates))


def resolve_parse_workers(value: str, effective_cpus: int, auto_max: int = 2) -> int:
    normalized = value.strip().lower()
    if normalized == "auto":
        # Four independent sensors may share this host. Reserve a conservative
        # quarter of the effective CPU budget per sensor and cap it explicitly.
        per_sensor_budget = max(1, effective_cpus // 4)
        return min(max(1, auto_max), per_sensor_budget)
    try:
        requested = int(normalized)
    except ValueError as exc:
        raise ValueError("GMJFLOW_PMACCT_PARSE_WORKERS must be a positive integer or 'auto'") from exc
    if requested <= 0:
        raise ValueError("GMJFLOW_PMACCT_PARSE_WORKERS must be greater than zero")
    return min(requested, max(1, effective_cpus))


def get_client():
    import clickhouse_connect

    return clickhouse_connect.get_client(
        host=os.getenv("CLICKHOUSE_HOST", "localhost"),
        port=env_int("CLICKHOUSE_PORT", 8123),
        username=os.getenv("CLICKHOUSE_USER", "default"),
        password=os.getenv("CLICKHOUSE_PASSWORD", ""),
        database=os.getenv("CLICKHOUSE_DATABASE", "flowdb"),
    )


def normalize_key(value: str) -> str:
    return value.strip().strip('"').strip("'").lower().replace("-", "_").replace(" ", "_")


def normalize_record_keys(record: dict[str, Any]) -> dict[str, Any]:
    return {normalize_key(str(key)): value for key, value in record.items()}


def pick(record: dict[str, Any], field: str, default: Any = None) -> Any:
    for alias in ALIASES[field]:
        key = normalize_key(alias)
        if key in record and record[key] not in (None, "", "null", "NULL"):
            return record[key]
    return default


def safe_int(value: Any, default: int = 0, minimum: int = 0, maximum: int | None = None) -> int:
    try:
        if isinstance(value, str) and value.lower().startswith("0x"):
            number = int(value, 16)
        else:
            number = int(float(value))
    except (TypeError, ValueError):
        number = default
    number = max(minimum, number)
    if maximum is not None:
        number = min(maximum, number)
    return number


def safe_ip(value: Any, default: str = "::") -> str:
    try:
        return str(ip_address(str(value).strip()))
    except ValueError:
        return default


def parse_proto(value: Any) -> int:
    if value is None:
        return 0
    text = str(value).strip().lower()
    if text in PROTO_BY_NAME:
        return PROTO_BY_NAME[text]
    return safe_int(text, default=0, minimum=0, maximum=255)


def proto_name(proto: int) -> str:
    return PROTO_NAMES.get(proto, f"PROTO-{proto}")


def parse_tcp_flags(value: Any) -> int:
    if value is None:
        return 0
    text = str(value).strip().lower()
    if not text:
        return 0
    if text.startswith("0x") or text.replace(".", "", 1).isdigit():
        return safe_int(text, default=0, minimum=0, maximum=65535)

    flags = 0
    for token in text.replace("+", " ").replace("|", " ").replace(",", " ").split():
        flags |= TCP_FLAG_BY_NAME.get(token, 0)
    return flags


def tcp_flags_name(flags: int) -> str:
    names = [name for bit, name in TCP_FLAG_BITS if flags & bit]
    return "+".join(names) if names else "NONE"


def parse_timestamp(value: Any) -> datetime:
    if value not in (None, "", "null", "NULL"):
        text = str(value).strip()
        try:
            if text.replace(".", "", 1).isdigit():
                number = float(text)
                if number > 10_000_000_000:
                    number /= 1000
                return datetime.fromtimestamp(number, tz=timezone.utc)
        except (OverflowError, ValueError):
            pass

        iso_text = text.replace("Z", "+00:00")
        for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                if fmt is None:
                    parsed = datetime.fromisoformat(iso_text)
                else:
                    parsed = datetime.strptime(text, fmt)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc)
            except ValueError:
                continue

    return datetime.now(timezone.utc)


def parse_optional_timestamp(value: Any) -> datetime | None:
    if value in (None, "", "null", "NULL"):
        return None
    return parse_timestamp(value)


def parse_duration_ms(value: Any, start: datetime | None = None, end: datetime | None = None) -> int:
    duration = safe_int(value, default=0, minimum=0)
    if duration > 0:
        return duration
    if start and end and end > start:
        return max(0, int((end - start).total_seconds() * 1000))
    return 0


def normalize_flow(record: dict[str, Any], sensor: str, exporter_ip: str, sample_rate_default: int) -> tuple:
    normalized = normalize_record_keys(record)
    proto = parse_proto(pick(normalized, "proto", 0))
    tcp_flags = parse_tcp_flags(pick(normalized, "tcpflags", 0))
    sample_rate = safe_int(pick(normalized, "sample_rate", sample_rate_default), default=sample_rate_default, minimum=1)
    flow_count = safe_int(pick(normalized, "flows", 1), default=1, minimum=1)
    flow_start = parse_optional_timestamp(pick(normalized, "flow_start"))
    flow_end = parse_optional_timestamp(pick(normalized, "flow_end"))
    duration_ms = parse_duration_ms(pick(normalized, "duration_ms"), flow_start, flow_end)

    # Names are kept here for debugging/future enrichment; flow_raw stores compact numeric values.
    _ = (proto_name(proto), tcp_flags_name(tcp_flags))

    return (
        parse_timestamp(pick(normalized, "timestamp")),
        sensor,
        safe_ip(exporter_ip),
        safe_ip(pick(normalized, "src_host")),
        safe_ip(pick(normalized, "dst_host")),
        safe_int(pick(normalized, "src_port", 0), minimum=0, maximum=65535),
        safe_int(pick(normalized, "dst_port", 0), minimum=0, maximum=65535),
        proto,
        tcp_flags,
        safe_int(pick(normalized, "in_iface", 0), minimum=0),
        safe_int(pick(normalized, "out_iface", 0), minimum=0),
        safe_int(pick(normalized, "bytes", 0), minimum=0),
        safe_int(pick(normalized, "packets", 0), minimum=0),
        flow_count,
        "netflow-v9",
        sample_rate,
        flow_start,
        flow_end,
        duration_ms,
        safe_int(pick(normalized, "src_as", 0), minimum=0),
        safe_int(pick(normalized, "dst_as", 0), minimum=0),
        str(pick(normalized, "src_as_name", "") or "")[:255],
        str(pick(normalized, "dst_as_name", "") or "")[:255],
    )


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    directory_fd: int | None = None
    try:
        with temp_path.open("x", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        if os.name != "nt":
            directory_fd = os.open(
                str(path.parent),
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            os.fsync(directory_fd)
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
        temp_path.unlink(missing_ok=True)


def _checkpoint_nonnegative_int(payload: dict[str, Any], key: str, default: int | None = None) -> int:
    value = payload.get(key, default)
    if isinstance(value, bool) or value is None:
        raise CheckpointError(f"checkpoint field {key!r} is missing or invalid")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise CheckpointError(f"checkpoint field {key!r} is invalid") from exc
    if parsed < 0:
        raise CheckpointError(f"checkpoint field {key!r} must not be negative")
    return parsed


class Tailer:
    def __init__(self, path: Path, state_path: Path, start_from_end_if_no_state: bool = False):
        self.path = path
        self.state_path = state_path
        self.offset = 0
        self.inode = 0
        self.pending_offset = 0
        self.last_read_bytes = 0
        self.last_read_limit_reached = False
        self.last_read_incomplete = False
        state_status = self.load_state()
        if state_status is CheckpointStatus.MISSING and start_from_end_if_no_state and self.path.exists():
            stat = self.path.stat()
            self.offset = stat.st_size
            self.pending_offset = self.offset
            self.inode = getattr(stat, "st_ino", 0)
            self.commit(force=True)
            print(
                f"No parser checkpoint found; starting at EOF for existing file {self.path} offset={self.offset}",
                flush=True,
            )

    def load_state(self) -> CheckpointStatus:
        try:
            raw = self.state_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return CheckpointStatus.MISSING
        except OSError as exc:
            raise CheckpointError(f"cannot read existing checkpoint {self.state_path}: {exc}") from exc
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise CheckpointError(f"corrupt checkpoint JSON in {self.state_path}: {exc}") from exc
        if not isinstance(payload, dict):
            raise CheckpointError(f"checkpoint {self.state_path} must contain a JSON object")
        if payload.get("file") != str(self.path):
            raise CheckpointError(
                f"checkpoint {self.state_path} belongs to {payload.get('file')!r}, not {self.path}"
            )
        self.offset = _checkpoint_nonnegative_int(payload, "offset")
        self.pending_offset = self.offset
        self.inode = _checkpoint_nonnegative_int(payload, "inode", default=0)
        return CheckpointStatus.LOADED

    def commit(self, last_line_ts: str = "", force: bool = False) -> None:
        if self.pending_offset <= 0 and not force:
            return
        next_offset = self.pending_offset if self.pending_offset > 0 else self.offset
        payload = {
            "file": str(self.path),
            "inode": self.inode,
            "offset": next_offset,
            "last_line_ts": last_line_ts,
            "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        atomic_write_json(self.state_path, payload)
        self.offset = next_offset
        self.pending_offset = next_offset

    def rollback_pending(self) -> None:
        self.pending_offset = self.offset

    def reset_for_new_file(self) -> None:
        self.offset = 0
        self.pending_offset = 0
        if self.path.exists():
            self.inode = getattr(self.path.stat(), "st_ino", 0)
        else:
            self.inode = 0
        self.commit(force=True)

    def read_lines(
        self,
        max_bytes: int = 4 * 1024 * 1024,
        max_lines: int = 20000,
    ) -> list[str]:
        if max_bytes <= 0 or max_lines <= 0:
            raise ValueError("max_bytes and max_lines must be greater than zero")
        self.last_read_bytes = 0
        self.last_read_limit_reached = False
        self.last_read_incomplete = False
        if not self.path.exists():
            return []

        stat = self.path.stat()
        size = stat.st_size
        inode = getattr(stat, "st_ino", 0)

        if inode and self.inode and inode != self.inode:
            self.offset = 0
            self.pending_offset = 0

        self.inode = inode

        read_offset = max(self.offset, self.pending_offset)
        if size < read_offset:
            self.offset = 0
            self.pending_offset = 0
            read_offset = 0

        lines: list[str] = []
        consumed = 0

        with self.path.open("rb") as handle:
            handle.seek(read_offset)

            while len(lines) < max_lines:
                raw = handle.readline()

                if not raw:
                    break

                # Nao avanca o checkpoint sobre uma linha ainda incompleta.
                if not raw.endswith(b"\n"):
                    self.last_read_incomplete = True
                    break
                if consumed + len(raw) > max_bytes:
                    self.last_read_limit_reached = True
                    if not lines:
                        raise ValueError(
                            f"complete pmacct line exceeds PMACCT_PARSER_MAX_BYTES={max_bytes}"
                        )
                    break

                consumed += len(raw)
                lines.append(
                    raw.decode("utf-8", errors="ignore").rstrip("\r\n")
                )

        if consumed <= 0:
            return []

        self.last_read_bytes = consumed
        self.pending_offset = read_offset + consumed
        if len(lines) >= max_lines:
            self.last_read_limit_reached = True
        return lines

    def backlog_bytes(self) -> int:
        try:
            return max(0, self.path.stat().st_size - self.pending_offset)
        except OSError:
            return 0


def parse_json_line(line: str) -> list[dict[str, Any]]:
    payload = json.loads(line)
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def header_like(row: list[str]) -> bool:
    return any(normalize_key(value) in KNOWN_HEADER_FIELDS for value in row)


def csv_fields_from_env() -> list[str]:
    raw = os.getenv("PMACCT_CSV_FIELDS", "")
    if not raw.strip():
        return DEFAULT_CSV_FIELDS
    return [normalize_key(field) for field in raw.split(",") if field.strip()]


def parse_csv_line(line: str, delimiter: str, fallback_fields: list[str], headers: list[str] | None) -> tuple[list[dict[str, Any]], list[str] | None]:
    row = next(csv.reader([line], delimiter=delimiter))
    if not row:
        return [], headers
    if header_like(row):
        return [], [normalize_key(value) for value in row]

    fields = headers if headers else fallback_fields
    if len(row) < len(fields):
        missing = set(fields[len(row):])
        if not missing.issubset({"flows", "flow_count", "records"}):
            return [], headers
    record = dict(zip(fields[: len(row)], row))
    return [record], headers


def _possible_csv_header(line: str, delimiter: str) -> bool:
    normalized_line = line.lower().replace("-", "_").replace(" ", "_")
    if not any(alias in normalized_line for alias in KNOWN_HEADER_FIELDS):
        return False
    try:
        return header_like(next(csv.reader([line], delimiter=delimiter)))
    except (csv.Error, StopIteration):
        return False


def prepare_parse_chunks(
    lines: list[str],
    config: ParserConfig,
    workers: int,
) -> tuple[list[ParseChunk], int, tuple[str, ...] | None]:
    current_headers = config.headers
    skipped = 0
    segments: list[tuple[tuple[str, ...] | None, list[str]]] = []
    segment: list[str] = []

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("!"):
            skipped += 1
            continue
        if (
            config.output_format != "json"
            and not line.startswith(("{", "["))
            and _possible_csv_header(line, config.delimiter)
        ):
            if segment:
                segments.append((current_headers, segment))
                segment = []
            row = next(csv.reader([line], delimiter=config.delimiter))
            current_headers = tuple(normalize_key(value) for value in row)
            skipped += 1
            continue
        segment.append(line)

    if segment:
        segments.append((current_headers, segment))

    data_line_count = sum(len(item[1]) for item in segments)
    if data_line_count <= 0:
        return [], skipped, current_headers
    target_chunks = max(1, min(data_line_count, workers))
    chunk_size = max(1, math.ceil(data_line_count / target_chunks))
    chunks: list[ParseChunk] = []
    for headers, segment_lines in segments:
        for start in range(0, len(segment_lines), chunk_size):
            chunk_config = ParserConfig(
                output_format=config.output_format,
                delimiter=config.delimiter,
                fallback_fields=config.fallback_fields,
                headers=headers,
                sensor=config.sensor,
                exporter_ip=config.exporter_ip,
                sample_rate=config.sample_rate,
            )
            chunks.append(
                ParseChunk(
                    index=len(chunks),
                    lines=tuple(segment_lines[start : start + chunk_size]),
                    config=chunk_config,
                )
            )
    return chunks, skipped, current_headers


def parse_chunk(chunk: ParseChunk) -> ParsedChunkResult:
    started = time.perf_counter()
    rows: list[tuple] = []
    invalid_count = 0
    errors: list[str] = []
    last_line_ts = ""
    normalize_seconds = 0.0
    headers = list(chunk.config.headers) if chunk.config.headers else None

    for line in chunk.lines:
        try:
            if chunk.config.output_format == "json" or line.startswith(("{", "[")):
                records = parse_json_line(line)
            else:
                records, headers = parse_csv_line(
                    line,
                    chunk.config.delimiter,
                    list(chunk.config.fallback_fields),
                    headers,
                )
            if not records:
                invalid_count += 1
                continue
            for record in records:
                normalize_started = time.perf_counter()
                flow = normalize_flow(
                    record,
                    chunk.config.sensor,
                    chunk.config.exporter_ip,
                    chunk.config.sample_rate,
                )
                normalize_seconds += time.perf_counter() - normalize_started
                rows.append(flow)
                last_line_ts = flow[0].isoformat().replace("+00:00", "Z")
        except Exception as exc:
            invalid_count += 1
            if len(errors) < 20:
                errors.append(f"{exc}: {line[:200]}")

    return ParsedChunkResult(
        index=chunk.index,
        rows=rows,
        valid_count=len(rows),
        invalid_count=invalid_count,
        errors=errors,
        last_line_ts=last_line_ts,
        parse_seconds=time.perf_counter() - started,
        normalize_seconds=normalize_seconds,
    )


def reassemble_chunk_results(
    results: list[ParsedChunkResult],
    expected_indices: Iterable[int],
) -> list[ParsedChunkResult]:
    expected = list(expected_indices)
    by_index: dict[int, ParsedChunkResult] = {}
    for result in results:
        if not isinstance(result, ParsedChunkResult):
            raise ParallelParseError("parser worker returned an invalid result type")
        if result.index in by_index:
            raise ParallelParseError(f"parser worker returned duplicate chunk {result.index}")
        if result.valid_count != len(result.rows) or result.invalid_count < 0:
            raise ParallelParseError(f"parser worker returned inconsistent counters for chunk {result.index}")
        by_index[result.index] = result
    if set(by_index) != set(expected):
        raise ParallelParseError(
            f"parser worker result set mismatch: expected={expected}, got={sorted(by_index)}"
        )
    return [by_index[index] for index in sorted(expected)]


def _collect_parallel_chunks(
    chunks: list[ParseChunk],
    executor: Executor,
    worker_fn: Callable[[ParseChunk], ParsedChunkResult],
) -> list[ParsedChunkResult]:
    futures: dict[Future, int] = {}
    results: list[ParsedChunkResult] = []
    try:
        for chunk in chunks:
            futures[executor.submit(worker_fn, chunk)] = chunk.index
        for future in as_completed(futures):
            expected_index = futures[future]
            result = future.result()
            if not isinstance(result, ParsedChunkResult) or result.index != expected_index:
                raise ParallelParseError(
                    f"parser worker returned invalid result for chunk {expected_index}"
                )
            results.append(result)
    except Exception as exc:
        for future in futures:
            future.cancel()
        if isinstance(exc, ParallelParseError):
            raise
        raise ParallelParseError(f"parser worker failed: {exc}") from exc
    return results


def parse_batch(
    lines: list[str],
    config: ParserConfig,
    workers: int,
    *,
    executor: Executor | None = None,
    worker_fn: Callable[[ParseChunk], ParsedChunkResult] = parse_chunk,
) -> ParsedBatchResult:
    parallel_started = time.perf_counter()
    chunks, preprocessing_skipped, headers = prepare_parse_chunks(lines, config, workers)
    preparation_seconds = time.perf_counter() - parallel_started
    if workers <= 1:
        unordered_results = [worker_fn(chunk) for chunk in chunks]
    elif executor is not None:
        unordered_results = _collect_parallel_chunks(chunks, executor, worker_fn)
    else:
        with ProcessPoolExecutor(
            max_workers=workers,
            mp_context=multiprocessing.get_context("spawn"),
        ) as temporary_executor:
            unordered_results = _collect_parallel_chunks(chunks, temporary_executor, worker_fn)
    ordered_results = reassemble_chunk_results(
        unordered_results,
        (chunk.index for chunk in chunks),
    )
    rows = [row for result in ordered_results for row in result.rows]
    errors = [error for result in ordered_results for error in result.errors]
    last_line_ts = next(
        (result.last_line_ts for result in reversed(ordered_results) if result.last_line_ts),
        "",
    )
    return ParsedBatchResult(
        rows=rows,
        valid_count=sum(result.valid_count for result in ordered_results),
        invalid_count=preprocessing_skipped
        + sum(result.invalid_count for result in ordered_results),
        errors=errors,
        last_line_ts=last_line_ts,
        headers=headers,
        chunk_count=len(chunks),
        parse_seconds=sum(result.parse_seconds for result in ordered_results),
        normalize_seconds=sum(result.normalize_seconds for result in ordered_results),
        parallel_parse_seconds=time.perf_counter() - parallel_started,
        preparation_seconds=preparation_seconds,
        max_chunk_parse_seconds=max(
            (result.parse_seconds for result in ordered_results),
            default=0.0,
        ),
    )


class ParallelParser:
    def __init__(
        self,
        workers: int,
        *,
        executor_factory: Callable[..., Executor] = ProcessPoolExecutor,
        worker_fn: Callable[[ParseChunk], ParsedChunkResult] = parse_chunk,
    ):
        self.workers = workers
        self.worker_fn = worker_fn
        self.executor = (
            executor_factory(
                max_workers=workers,
                mp_context=multiprocessing.get_context("spawn"),
            )
            if workers > 1
            else None
        )
        self.closed = False

    def parse(self, lines: list[str], config: ParserConfig) -> ParsedBatchResult:
        if self.closed:
            raise RuntimeError("parser pool is closed")
        return parse_batch(
            lines,
            config,
            self.workers,
            executor=self.executor,
            worker_fn=self.worker_fn,
        )

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.executor is not None:
            self.executor.shutdown(wait=True, cancel_futures=True)

    def __enter__(self) -> "ParallelParser":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


class ClickHouseWriter:
    """Single-process, single-inflight INSERT writer with safe context reuse."""

    def __init__(self, client):
        self.client = client
        self.context = None
        self.context_attempted = False
        self.context_error = ""

    def _ensure_context(self) -> None:
        if self.context_attempted:
            return
        self.context_attempted = True
        create_context = getattr(self.client, "create_insert_context", None)
        if not callable(create_context):
            self.context_error = "create_insert_context unavailable"
            return
        try:
            self.context = create_context(table="flow_raw", column_names=COLUMN_NAMES)
        except Exception as exc:
            self.context_error = str(exc)
            self.context = None

    def insert(self, rows: list[tuple]) -> bool:
        self._ensure_context()
        if self.context is not None:
            self.context.data = rows
            self.client.insert(context=self.context)
            return True
        self.client.insert("flow_raw", rows, column_names=COLUMN_NAMES)
        return False


def ingest_pending_batch(
    tailer: Tailer,
    writer: ClickHouseWriter,
    parser: ParallelParser,
    lines: list[str],
    config: ParserConfig,
    *,
    stop_requested: Callable[[], bool] = lambda: False,
) -> IngestionResult:
    try:
        parsed = parser.parse(lines, config)
    except Exception:
        tailer.rollback_pending()
        raise
    if stop_requested():
        tailer.rollback_pending()
        raise ShutdownRequested("shutdown requested before INSERT")

    insert_seconds = 0.0
    context_reused = False
    try:
        if parsed.rows:
            insert_started = time.perf_counter()
            context_reused = writer.insert(parsed.rows)
            insert_seconds = time.perf_counter() - insert_started
        commit_started = time.perf_counter()
        tailer.commit(parsed.last_line_ts)
        commit_seconds = time.perf_counter() - commit_started
    except Exception:
        tailer.rollback_pending()
        raise
    return IngestionResult(
        parsed=parsed,
        insert_seconds=insert_seconds,
        commit_seconds=commit_seconds,
        insert_context_reused=context_reused,
    )


class ShutdownController:
    def __init__(self) -> None:
        self.requested = False

    def request(self, signum, _frame) -> None:
        self.requested = True
        print(f"pmacct parser shutdown requested by signal {signum}", flush=True)


def should_poll_sleep(backlog_bytes: int, incomplete_line: bool = False) -> bool:
    return backlog_bytes <= 0 or incomplete_line


def write_status(status_file: Path, payload: dict[str, Any]) -> None:
    status_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = status_file.with_suffix(status_file.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(status_file)


def compress_file(path: Path) -> Path:
    """Atomically compress `path` to `path.gz`.

    The gzip stream is written to `path.gz.part` and only renamed into place
    once complete, so a `*.csv.gz` always means a complete archive and a stale
    `*.gz.part` is never mistaken for one.
    """
    gz_path = path.with_suffix(path.suffix + ".gz")
    part = gz_path.with_name(gz_path.name + ".part")
    part.unlink(missing_ok=True)
    with path.open("rb") as source, gzip.open(part, "wb") as target:
        shutil.copyfileobj(source, target)
    os.replace(part, gz_path)
    path.unlink(missing_ok=True)
    return gz_path


def rotation_checkpoint_path(path: Path) -> Path:
    return path.with_name(f"{path.name}.processed.json")


def rotation_cleanup_eligible(path: Path, checkpoint: dict[str, Any]) -> bool:
    name = path.name.lower()
    if "backlog" in name or not re.search(r"-\d{8}-\d{6}\.csv(?:\.gz)?$", name):
        return False
    try:
        offset = int(checkpoint.get("offset"))
        file_size = int(checkpoint.get("file_size"))
        lag_bytes = int(checkpoint.get("lag_bytes"))
    except (TypeError, ValueError):
        return False
    return bool(
        checkpoint.get("checkpoint_valid") is True
        and checkpoint.get("ingestion_complete") is True
        and checkpoint.get("archive") == str(path)
        and file_size >= 0
        and offset >= file_size
        and lag_bytes == 0
    )


def cleanup_old_rotations(directory: Path, keep_days: int, active_file: Path | None = None) -> int:
    if keep_days <= 0 or not directory.exists():
        return 0
    cutoff = time.time() - keep_days * 86400
    deleted = 0
    candidates = [*directory.glob("*.csv"), *directory.glob("*.csv.gz")]
    for path in candidates:
        try:
            if active_file is not None and path.resolve() == active_file.resolve():
                continue
            checkpoint_path = rotation_checkpoint_path(path)
            try:
                checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if path.stat().st_mtime < cutoff and rotation_cleanup_eligible(path, checkpoint):
                path.unlink()
                if checkpoint_path.exists():
                    checkpoint_path.unlink()
                deleted += 1
        except (OSError, RuntimeError):
            continue
    return deleted


def read_complete_lines(path: Path, start_offset: int) -> list[str]:
    """Read whole lines from `start_offset` to EOF of a closed file.

    Mirrors the Tailer boundary rule: a trailing line without a newline is
    never consumed, so it is left for a subsequent pass.
    """
    if not path.exists():
        return []
    lines: list[str] = []
    with path.open("rb") as handle:
        if start_offset > 0:
            handle.seek(start_offset)
        while True:
            raw = handle.readline()
            if not raw:
                break
            if not raw.endswith(b"\n"):
                break
            lines.append(raw.decode("utf-8", errors="ignore").rstrip("\r\n"))
    return lines


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def rotation_journal_path(output_file: Path, tailer: Tailer) -> Path:
    return tailer.state_path.parent / f"{output_file.name}.rotation.json"


def parse_raw_line(
    line: str,
    output_format: str,
    delimiter: str,
    fallback_fields: list[str],
    headers: list[str] | None,
) -> tuple[list[dict[str, Any]], list[str] | None]:
    if output_format == "json" or line.startswith("{") or line.startswith("["):
        return parse_json_line(line), headers
    return parse_csv_line(line, delimiter, fallback_fields, headers)


def parse_lines_to_flows(
    raw_lines: list[str],
    output_format: str,
    delimiter: str,
    fallback_fields: list[str],
    headers: list[str] | None,
    sensor: str,
    exporter_ip: str,
    sample_rate: int,
) -> tuple[list[tuple], list[str] | None, int, int]:
    """Parse raw pmacct lines into normalized flow tuples.

    Returns (flows, headers, read_count, skipped_count).
    """
    flows: list[tuple] = []
    read = 0
    skipped = 0
    for raw_line in raw_lines:
        line = raw_line.strip()
        if not line or line.startswith("!"):
            skipped += 1
            continue
        read += 1
        try:
            records, headers = parse_raw_line(line, output_format, delimiter, fallback_fields, headers)
            if not records:
                skipped += 1
            for record in records:
                flows.append(normalize_flow(record, sensor, exporter_ip, sample_rate))
        except Exception:
            skipped += 1
    return flows, headers, read, skipped


def _wait_for_producer_reopen(output_file: Path, old_inode: int, reopen_timeout_seconds: float) -> None:
    deadline = time.monotonic() + reopen_timeout_seconds
    while time.monotonic() < deadline:
        if output_file.exists():
            new_stat = output_file.stat()
            if getattr(new_stat, "st_ino", 0) != old_inode:
                return
        time.sleep(0.2)
    raise RuntimeError("pmacct rotation blocked: producer did not reopen the output file")


def begin_rotation(
    output_file: Path,
    tailer: Tailer,
    reopen_timeout_seconds: float = 30.0,
) -> tuple[Path, Path, int]:
    """Persist the rotation intent, atomically rename the active CSV and wait
    for the producer to recreate it. Returns (rotated, journal, drain_offset).
    """
    if not output_file.exists():
        raise RuntimeError("active pmacct CSV does not exist")

    source_stat = output_file.stat()
    source_inode = getattr(source_stat, "st_ino", 0)
    source_size = source_stat.st_size

    checkpoint = read_json(tailer.state_path)
    if checkpoint is None or checkpoint.get("file") != str(output_file):
        raise RuntimeError("pmacct rotation requires a valid parser checkpoint")

    drain_offset = safe_int(checkpoint.get("offset"), default=0, minimum=0)

    # The rename itself is O(1): no copy of the growing file is ever made.
    # Compression later writes a .gz of ~24% of the source, so reserve ~35%
    # of the source size (or a 2 GiB floor) before starting.
    disk = shutil.disk_usage(output_file.parent)
    required_free = max(2 * 1024**3, int(source_size * 0.35))
    if disk.free < required_free:
        raise RuntimeError(
            "pmacct rotation blocked: insufficient free disk space "
            f"(free={disk.free}, required={required_free}, source={source_size})"
        )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    rotated = output_file.with_name(f"{output_file.stem}-{timestamp}{output_file.suffix}")
    journal = rotation_journal_path(output_file, tailer)

    atomic_write_json(
        journal,
        {
            "active_path": str(output_file),
            "rotated_path": str(rotated),
            "old_inode": source_inode,
            "drain_offset": drain_offset,
            "state": "RENAMED",
            "started_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
    )

    # Atomic rename: the producer keeps its open descriptor and keeps appending
    # to the renamed inode until its next refresh cycle.
    os.replace(output_file, rotated)

    try:
        _wait_for_producer_reopen(output_file, source_inode, reopen_timeout_seconds)
    except Exception:
        # Producer is not reopening: put the file back and drop the intent so a
        # later attempt starts clean (no orphan, no loss).
        if not output_file.exists() and rotated.exists():
            os.replace(rotated, output_file)
        journal.unlink(missing_ok=True)
        raise

    return rotated, journal, drain_offset


def mark_rotation_ingested(journal: Path, drained_size: int) -> None:
    payload = read_json(journal)
    if payload is None:
        return
    payload["state"] = "INGESTED"
    payload["drained_size"] = drained_size
    payload["ingested_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    atomic_write_json(journal, payload)


def finish_rotation(
    rotated: Path,
    journal: Path,
    output_file: Path,
    tailer: Tailer,
    compress: bool,
    keep_days: int,
) -> dict[str, Any]:
    """Finalize an ingested rotation: compress atomically, write the archive
    checkpoint, reset the tailer and clear the rotation journal. Idempotent."""
    final_path = rotated.with_suffix(rotated.suffix + ".gz") if compress else rotated
    drained_size = (
        rotated.stat().st_size
        if rotated.exists()
        else safe_int((read_json(journal) or {}).get("drained_size"), default=0, minimum=0)
    )

    if compress:
        if rotated.exists():
            final_path = compress_file(rotated)
        elif not final_path.exists():
            raise RuntimeError("pmacct rotation: rotated CSV and archive are both missing")

    write_status(
        rotation_checkpoint_path(final_path),
        {
            "archive": str(final_path),
            "source_file": str(output_file),
            "file_size": drained_size,
            "offset": drained_size,
            "lag_bytes": 0,
            "checkpoint_valid": True,
            "ingestion_complete": True,
            "completed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        },
    )

    tailer.reset_for_new_file()
    deleted = cleanup_old_rotations(output_file.parent, keep_days, active_file=output_file)
    journal.unlink(missing_ok=True)

    return {
        "rotated_to": str(final_path),
        "method": "rename-reopen",
        "compressed": compress,
        "deleted_old_rotations": deleted,
        "rotated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def drain_and_finalize_rotation(
    rotated: Path,
    journal: Path,
    drain_offset: int,
    output_file: Path,
    tailer: Tailer,
    compress: bool,
    keep_days: int,
    ingest: Callable[[list[str]], int],
) -> dict[str, Any]:
    """Drain the rotated file, ingest it via `ingest`, then finalize."""
    tail_lines = read_complete_lines(rotated, drain_offset)
    if tail_lines:
        ingest(tail_lines)
    drained_size = rotated.stat().st_size if rotated.exists() else 0
    mark_rotation_ingested(journal, drained_size)
    return finish_rotation(rotated, journal, output_file, tailer, compress, keep_days)


def recover_interrupted_rotation(
    output_file: Path,
    tailer: Tailer,
    compress: bool,
    keep_days: int,
    ingest: Callable[[list[str]], int],
    reopen_timeout_seconds: float = 30.0,
) -> bool:
    """Resume an interrupted rotation after a crash/restart.

    - state RENAMED: the rename happened but the tail was not yet drained; the
      rotated file is drained, ingested, marked INGESTED and finalized.
    - state INGESTED: only finalization (compress/reset/cleanup) is missing.
    Returns True when an interrupted rotation was recovered.
    """
    journal = rotation_journal_path(output_file, tailer)
    payload = read_json(journal)
    if payload is None:
        return False

    rotated = Path(payload.get("rotated_path", ""))
    state = payload.get("state")

    if state == "RENAMED":
        if not rotated.is_file():
            journal.unlink(missing_ok=True)
            return False
        old_inode = safe_int(payload.get("old_inode"), default=0, minimum=0)
        active_inode = getattr(output_file.stat(), "st_ino", 0) if output_file.exists() else 0
        if not output_file.exists() or active_inode == old_inode:
            try:
                _wait_for_producer_reopen(output_file, old_inode, reopen_timeout_seconds)
            except Exception:
                # Producer not back, or the active path is a stale/restored inode:
                # keep the journal and the rotated file for a future restart;
                # never lose data.
                return False
        drain_offset = safe_int(payload.get("drain_offset"), default=0, minimum=0)
        drain_and_finalize_rotation(rotated, journal, drain_offset, output_file, tailer, compress, keep_days, ingest)
        return True

    if state == "INGESTED":
        if rotated.is_file() or (compress and rotated.with_suffix(rotated.suffix + ".gz").is_file()):
            finish_rotation(rotated, journal, output_file, tailer, compress, keep_days)
        else:
            journal.unlink(missing_ok=True)
        return True

    journal.unlink(missing_ok=True)
    return False

def main() -> None:
    output_file = Path(os.getenv("PMACCT_OUTPUT_FILE", "/var/spool/pmacct/nfacctd.csv"))
    output_format = os.getenv("PMACCT_OUTPUT_FORMAT", "csv").lower()
    delimiter = os.getenv("PMACCT_CSV_DELIMITER", ",")
    sensor = os.getenv("PMACCT_SENSOR", "mikrotik-lab")
    exporter_ip = os.getenv("PMACCT_EXPORTER_IP", "192.168.0.157")
    sample_rate = env_int("PMACCT_SAMPLE_RATE", 1)
    batch_size = env_int("PMACCT_PARSER_BATCH_SIZE", 20000)
    batch_max_bytes = env_int("PMACCT_PARSER_MAX_BYTES", 4 * 1024 * 1024)
    flush_seconds = env_int("PMACCT_PARSER_FLUSH_SECONDS", 5)
    poll_seconds = float(os.getenv("PMACCT_PARSER_POLL_SECONDS", "1"))
    state_dir = Path(os.getenv("PMACCT_STATE_DIR", "/var/spool/pmacct/state"))
    state_file = Path(os.getenv("PMACCT_STATE_FILE", state_dir / f"{output_file.name}.offset.json"))
    status_file = Path(os.getenv("PMACCT_STATUS_FILE", state_dir / f"{output_file.name}.status.json"))
    rotate_enabled = env_bool("GMJFLOW_PMACCT_ROTATE_ENABLED", True)
    rotate_max_mb = env_int("GMJFLOW_PMACCT_ROTATE_MAX_MB", 100)
    rotate_keep_days = env_int("GMJFLOW_PMACCT_ROTATE_KEEP_DAYS", 3)
    rotate_compress = env_bool("GMJFLOW_PMACCT_ROTATE_COMPRESS", True)
    rotate_check_seconds = env_int("GMJFLOW_PMACCT_ROTATE_CHECK_SECONDS", 30)
    rotate_failure_cooldown_seconds = env_int("GMJFLOW_PMACCT_ROTATE_FAILURE_COOLDOWN_SECONDS", 900)
    start_from_end = env_bool("PMACCT_PARSER_START_FROM_END_IF_NO_STATE", True)

    if batch_size <= 0:
        raise ValueError("PMACCT_PARSER_BATCH_SIZE must be greater than zero")
    if batch_max_bytes <= 0:
        raise ValueError("PMACCT_PARSER_MAX_BYTES must be greater than zero")
    if flush_seconds < 0 or poll_seconds < 0:
        raise ValueError("parser flush and poll intervals must not be negative")

    effective_cpus = effective_cpu_count()
    auto_max = env_int("GMJFLOW_PMACCT_PARSE_WORKERS_AUTO_MAX", 2)
    parse_workers = resolve_parse_workers(
        os.getenv("GMJFLOW_PMACCT_PARSE_WORKERS", "1"),
        effective_cpus,
        auto_max=auto_max,
    )
    fallback_fields = csv_fields_from_env()
    headers: list[str] | None = None
    raw_batch: list[str] = []
    raw_batch_bytes = 0
    last_flush = time.monotonic()
    tailer = Tailer(output_file, state_file, start_from_end_if_no_state=start_from_end)
    client = get_client()
    writer = ClickHouseWriter(client)
    shutdown = ShutdownController()
    signal.signal(signal.SIGTERM, shutdown.request)
    signal.signal(signal.SIGINT, shutdown.request)
    lines_read = 0
    lines_inserted = 0
    lines_skipped = 0
    last_line_ts = ""
    last_insert_at = ""
    last_error = ""
    last_rotation: dict[str, Any] | None = None
    last_rotate_check = 0.0
    last_rotate_failure = 0.0
    worker_failures = 0
    batch_sequence = 0

    print(
        f"Reading pmacct {output_format} from {output_file}; state={state_file}; "
        f"offset={tailer.offset}; parse_workers={parse_workers}; effective_cpus={effective_cpus}",
        flush=True,
    )
    parser = ParallelParser(parse_workers)

    def ingest(raw_lines: list[str]) -> int:
        nonlocal headers, lines_inserted, lines_skipped
        nonlocal rows_inserted_last_cycle, rows_skipped_last_cycle, last_line_ts
        config = ParserConfig(
            output_format=output_format,
            delimiter=delimiter,
            fallback_fields=tuple(fallback_fields),
            headers=tuple(headers) if headers else None,
            sensor=sensor,
            exporter_ip=exporter_ip,
            sample_rate=sample_rate,
        )
        parsed = parser.parse(raw_lines, config)
        if parsed.headers is not None:
            headers = list(parsed.headers)
        for error in parsed.errors:
            print(f"Skipping pmacct line: {error}", flush=True)
        if parsed.rows:
            writer.insert(parsed.rows)
            lines_inserted += len(parsed.rows)
            rows_inserted_last_cycle += len(parsed.rows)
        lines_skipped += len(parsed.errors)
        rows_skipped_last_cycle += len(parsed.errors)
        if parsed.last_line_ts:
            last_line_ts = parsed.last_line_ts
        return len(parsed.rows)

    try:
        if recover_interrupted_rotation(output_file, tailer, rotate_compress, rotate_keep_days, ingest):
            print("pmacct recovered an interrupted spool rotation", flush=True)
    except Exception as exc:
        print(f"pmacct rotation recovery failed: {exc}; will retry", flush=True)
    try:
        while not shutdown.requested:
            cycle_started = time.perf_counter()
            rows_read_last_cycle = 0
            rows_inserted_last_cycle = 0
            rows_skipped_last_cycle = 0
            read_seconds = 0.0
            parse_seconds = 0.0
            normalize_seconds = 0.0
            parallel_parse_seconds = 0.0
            insert_seconds = 0.0
            commit_seconds = 0.0
            batch_rows = 0
            completed_batch_bytes = 0
            chunk_count = 0
            insert_context_reused = False

            remaining_lines = batch_size - len(raw_batch)
            remaining_bytes = batch_max_bytes - raw_batch_bytes
            if remaining_lines > 0 and remaining_bytes > 0:
                read_started = time.perf_counter()
                new_lines = tailer.read_lines(
                    max_lines=remaining_lines,
                    max_bytes=remaining_bytes,
                )
                read_seconds = time.perf_counter() - read_started
                raw_batch.extend(new_lines)
                raw_batch_bytes += tailer.last_read_bytes
                newly_read = sum(
                    1
                    for line in new_lines
                    if line.strip() and not line.strip().startswith("!")
                )
                lines_read += newly_read
                rows_read_last_cycle = newly_read
            else:
                tailer.last_read_limit_reached = True

            if shutdown.requested:
                tailer.rollback_pending()
                break

            now_monotonic = time.monotonic()
            rotation_due = False
            if (
                rotate_enabled
                and now_monotonic - last_rotate_check >= rotate_check_seconds
                and now_monotonic - last_rotate_failure >= rotate_failure_cooldown_seconds
            ):
                last_rotate_check = now_monotonic
                if output_file.exists():
                    rotation_due = (
                        output_file.stat().st_size
                        >= max(1, rotate_max_mb) * 1024 * 1024
                    )

            flush_due = bool(raw_batch) and (
                len(raw_batch) >= batch_size
                or raw_batch_bytes >= batch_max_bytes
                or tailer.last_read_limit_reached
                or time.monotonic() - last_flush >= flush_seconds
                or rotation_due
            )
            if flush_due:
                batch_sequence += 1
                metadata = BatchMetadata(
                    sequence=batch_sequence,
                    file_generation=tailer.inode,
                    start_offset=tailer.offset,
                    end_offset=tailer.pending_offset,
                )
                parser_config = ParserConfig(
                    output_format=output_format,
                    delimiter=delimiter,
                    fallback_fields=tuple(fallback_fields),
                    headers=tuple(headers) if headers else None,
                    sensor=sensor,
                    exporter_ip=exporter_ip,
                    sample_rate=sample_rate,
                )
                try:
                    result = ingest_pending_batch(
                        tailer,
                        writer,
                        parser,
                        raw_batch,
                        parser_config,
                        stop_requested=lambda: shutdown.requested,
                    )
                except ShutdownRequested:
                    break
                except ParallelParseError as exc:
                    worker_failures += 1
                    last_error = str(exc)
                    print(f"pmacct parallel parser failed closed: {exc}", flush=True)
                    raise

                parsed = result.parsed
                if parsed.headers is not None:
                    headers = list(parsed.headers)
                if parsed.last_line_ts:
                    last_line_ts = parsed.last_line_ts
                for error in parsed.errors:
                    print(f"Skipping pmacct line: {error}", flush=True)
                if parsed.errors:
                    last_error = parsed.errors[-1]

                rows_inserted_last_cycle = len(parsed.rows)
                rows_skipped_last_cycle = parsed.invalid_count
                lines_inserted += rows_inserted_last_cycle
                lines_skipped += rows_skipped_last_cycle
                batch_rows = len(parsed.rows)
                completed_batch_bytes = raw_batch_bytes
                parse_seconds = parsed.parse_seconds
                normalize_seconds = parsed.normalize_seconds
                parallel_parse_seconds = parsed.parallel_parse_seconds
                insert_seconds = result.insert_seconds
                commit_seconds = result.commit_seconds
                chunk_count = parsed.chunk_count
                insert_context_reused = result.insert_context_reused
                if parsed.rows:
                    last_insert_at = (
                        datetime.now(timezone.utc)
                        .isoformat()
                        .replace("+00:00", "Z")
                    )
                raw_batch.clear()
                raw_batch_bytes = 0
                last_flush = time.monotonic()
                print(
                    "pmacct parser stats: "
                    f"file={output_file} sequence={metadata.sequence} "
                    f"range={metadata.start_offset}:{metadata.end_offset} "
                    f"read={lines_read} inserted={lines_inserted} "
                    f"skipped={lines_skipped} offset={tailer.offset} "
                    f"workers={parse_workers} chunks={chunk_count}",
                    flush=True,
                )

            if rotation_due and not raw_batch:
                try:
                    current_size = output_file.stat().st_size if output_file.exists() else 0
                    if tailer.offset >= current_size:
                        rotated_path, journal_path, drain_offset = begin_rotation(output_file, tailer)
                        summary = drain_and_finalize_rotation(
                            rotated_path,
                            journal_path,
                            drain_offset,
                            output_file,
                            tailer,
                            rotate_compress,
                            rotate_keep_days,
                            ingest,
                        )
                        last_rotation = summary
                        print(f"pmacct spool rotated: {summary}", flush=True)
                except Exception as exc:
                    last_error = str(exc)
                    last_rotate_failure = time.monotonic()
                    print(
                        f"pmacct rotation failed: {exc}; "
                        f"retry cooldown={rotate_failure_cooldown_seconds}s",
                        flush=True,
                    )

            file_size = output_file.stat().st_size if output_file.exists() else 0
            backlog_bytes = max(0, file_size - tailer.offset)
            cycle_seconds = time.perf_counter() - cycle_started
            rows_per_second = (
                rows_inserted_last_cycle / cycle_seconds if cycle_seconds > 0 else 0.0
            )
            bytes_per_second = (
                completed_batch_bytes / cycle_seconds if cycle_seconds > 0 else 0.0
            )
            try:
                write_status(
                    status_file,
                    {
                        "sensor": sensor,
                        "exporter_ip": exporter_ip,
                        "file": str(output_file),
                        "file_size_mb": round(file_size / 1024 / 1024, 3),
                        "rotate_enabled": rotate_enabled,
                        "rotate_max_mb": rotate_max_mb,
                        "rotate_keep_days": rotate_keep_days,
                        "rotate_compress": rotate_compress,
                        "offset": tailer.offset,
                        "inode": tailer.inode,
                        "lag_bytes": backlog_bytes,
                        "backlog_bytes": backlog_bytes,
                        "last_line_ts": last_line_ts,
                        "last_insert_at": last_insert_at,
                        "last_flow_time": last_line_ts,
                        "rows_read_last_cycle": rows_read_last_cycle,
                        "rows_inserted_last_cycle": rows_inserted_last_cycle,
                        "rows_skipped_last_cycle": rows_skipped_last_cycle,
                        "rows_read_total": lines_read,
                        "rows_inserted_total": lines_inserted,
                        "rows_skipped_total": lines_skipped,
                        "batch_sequence": batch_sequence,
                        "batch_rows": batch_rows,
                        "batch_bytes": completed_batch_bytes or raw_batch_bytes,
                        "batch_size_limit": batch_size,
                        "batch_bytes_limit": batch_max_bytes,
                        "parse_workers": parse_workers,
                        "effective_cpu_count": effective_cpus,
                        "chunk_count": chunk_count,
                        "worker_failures": worker_failures,
                        "read_seconds": read_seconds,
                        "parse_seconds": parse_seconds,
                        "normalize_seconds": normalize_seconds,
                        "serialize_seconds": 0.0,
                        "serialize_timing_available": False,
                        "parallel_parse_seconds": parallel_parse_seconds,
                        "parse_preparation_seconds": (
                            parsed.preparation_seconds if flush_due else 0.0
                        ),
                        "insert_seconds": insert_seconds,
                        "commit_seconds": commit_seconds,
                        "cycle_seconds": cycle_seconds,
                        "parse_ms": round(parallel_parse_seconds * 1000, 3),
                        "insert_ms": round(insert_seconds * 1000, 3),
                        "cycle_ms": round(cycle_seconds * 1000, 3),
                        "rows_per_second": rows_per_second,
                        "bytes_per_second": bytes_per_second,
                        "insert_context_reused": insert_context_reused,
                        "insert_context_fallback": writer.context_error,
                        "parser_status": "ok" if not last_error else "warning",
                        "last_error": last_error,
                        "last_rotation": last_rotation,
                        "updated_at": (
                            datetime.now(timezone.utc)
                            .isoformat()
                            .replace("+00:00", "Z")
                        ),
                    },
                )
            except Exception as exc:
                print(f"pmacct status write failed: {exc}", flush=True)

            immediate_backlog = tailer.backlog_bytes()
            if (
                not shutdown.requested
                and should_poll_sleep(
                    immediate_backlog,
                    incomplete_line=tailer.last_read_incomplete,
                )
            ):
                time.sleep(poll_seconds)
    finally:
        parser.close()
        close_client = getattr(client, "close", None)
        if callable(close_client):
            close_client()


if __name__ == "__main__":
    main()
